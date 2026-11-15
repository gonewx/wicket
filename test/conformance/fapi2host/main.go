// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Command fapi2host runs wicket with the high security profile on, set up for
// the FAPI 2.0 Security Profile authorization server test plan of the OpenID
// Foundation conformance suite.
//
// It serves HTTPS with a self-signed certificate made at startup, signs with
// a fresh ES256 key, registers two private_key_jwt clients that require DPoP
// and signs every authorization request in as the test user without a login
// form. Everything lives in memory. It is a test host, not a deployment
// template. With -config it also writes the suite configuration, including
// the private keys of both clients, to the given file.
//
// See docs/conformance/fapi2-security-profile.md for how it is run.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gonewx/godi"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/clientassertion"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/server"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/tokens"
	"github.com/gonewx/wicket/utils"
)

const subjectId = "alice"

func main() {
	addr := flag.String("addr", ":9443", "listen address")
	issuer := flag.String("issuer", "https://host.docker.internal:9443", "issuer, the base URL the suite reaches this host at")
	suiteBase := flag.String("suite", "https://localhost.emobix.co.uk:8443", "base URL of the conformance suite")
	alias := flag.String("alias", "wicket-fapi2", "test alias in the suite; the redirect URI is <suite>/test/a/<alias>/callback")
	configPath := flag.String("config", "", "write the suite configuration (with client private keys) to this file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger, *addr, strings.TrimRight(*issuer, "/"), strings.TrimRight(*suiteBase, "/"), *alias, *configPath); err != nil {
		logger.Error("fapi2host stopped", "err", err)
		os.Exit(1)
	}
}

// clientKey is the ES256 key a client signs its assertions with.
type clientKey struct {
	id      string
	kid     string
	private *ecdsa.PrivateKey
}

func newClientKey(id string) (*clientKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &clientKey{id: id, kid: id + "-key", private: key}, nil
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func (k *clientKey) jwk(private bool) map[string]any {
	// Uncompressed point: 0x04 || X || Y, 32 bytes each on P-256.
	point, _ := k.private.PublicKey.Bytes()
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": b64(point[1:33]), "y": b64(point[33:65]), "kid": k.kid, "use": "sig", "alg": "ES256"}
	if private {
		d, _ := k.private.Bytes()
		jwk["d"] = b64(d)
	}
	return jwk
}

func (k *clientKey) jwks(private bool) map[string]any {
	return map[string]any{"keys": []any{k.jwk(private)}}
}

func run(logger *slog.Logger, addr, issuer, suiteBase, alias, configPath string) error {
	redirectUri := suiteBase + "/test/a/" + alias + "/callback"
	keys := make([]*clientKey, 0, 2)
	for _, id := range []string{alias + "-client1", alias + "-client2"} {
		key, err := newClientKey(id)
		if err != nil {
			return err
		}
		keys = append(keys, key)
	}

	root, err := di.NewRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	cfg := root.ServerConfig()
	cfg.SetLogger(logger)

	signing, validation, err := serverSigningKey()
	if err != nil {
		return err
	}
	cfg.SetSigningCredentialStores(signing)
	cfg.SetValidationKeysStores(validation)

	// The suite sends the second client's redirect URI with a query.
	redirectUris := []string{redirectUri, redirectUri + "?dummy1=lorem&dummy2=ipsum"}
	clients := make([]*storage_models.Client, 0, len(keys))
	for i, key := range keys {
		client, err := fapiClient(key, redirectUris[i])
		if err != nil {
			return err
		}
		clients = append(clients, client)
	}
	cfg.SetClients(clients)
	cfg.SetIdentityScopes([]*storage_models.IdentityResource{
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesProfile(),
		storage_models.IdentityResourcesEmail(),
	})

	user := test.NewTestUser()
	user.SubjectId = subjectId
	user.Username = subjectId
	user.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesName), claimspkg.WithClaimValue("Alice Example")),
		claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesEmail), claimspkg.WithClaimValue("alice@example.com")),
	}
	userStore := test.NewTestUserStore([]*test.TestUser{user})
	cfg.SetProfileProvider(func() services.ProfileService { return test.NewTestUserProfileService(userStore, logger) })

	cfg.SetAuthenticationHandlerProvider(wicket.DefaultCookieAuthenticationScheme, func(p godi.Provider) auth.Handler {
		return integration_common.NewCookieAuthenticationHandler(godi.GetRequired[services.UserSession](p))
	})
	if err := godi.GetRequired[*authcore.SchemeProvider](root).AddScheme(
		auth.NewScheme(wicket.DefaultCookieAuthenticationScheme, "cookie"),
	); err != nil {
		return err
	}

	cfg.EnableHighSecurityProfile()
	cfg.SetPushedAuthorizationRequestStore(storage_memory.NewMemoryPushedAuthorizationRequestStore())
	cfg.SetPushedAuthorizationDataProtectionProvider(integration_common.NewPushedAuthorizationProtection())
	cfg.EnablePushedAuthorizationRequests(pushedauth.Options{})
	cfg.SetReplayRegistry(replay.NewMemoryRegistry())
	cfg.EnableDPoP(dpop.Options{})
	cfg.EnablePrivateKeyJwt(clientassertion.Options{})
	cfg.AllowInMemoryFallback()

	options := godi.GetRequired[*config_options.WicketOptions](root)
	options.IssuerUri = issuer
	options.KeyManagement.Enabled = false
	options.UserInteraction.LoginUrl = wicket.UIConstantsDefaultRoutePathsLogin
	options.UserInteraction.LoginReturnUrlParameter = wicket.UIConstantsDefaultRoutePathParamsLogin
	options.UserInteraction.LogoutUrl = wicket.UIConstantsDefaultRoutePathsLogout
	cfg.Freeze()

	srv, err := server.DefaultServer(root, server.WithLogger(logger))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc(utils.EnsureLeadingSlash(wicket.UIConstantsDefaultRoutePathsLogin), login(options))
	mux.HandleFunc(utils.EnsureLeadingSlash(wicket.UIConstantsDefaultRoutePathsConsent), consent(options))
	mux.HandleFunc(utils.EnsureLeadingSlash(wicket.UIConstantsDefaultRoutePathsError), errorPage(options))

	if configPath != "" {
		if err := writeSuiteConfig(configPath, issuer, alias, keys); err != nil {
			return err
		}
		logger.Info("suite configuration written", "path", configPath)
	}

	certificate, err := selfSignedCertificate(issuer)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           hosting.ScopeMiddleware(root)(srv.UseWicket()(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
			// FAPI 2.0 Security Profile §5.2.2: TLS 1.2 limited to these suites.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		},
	}
	logger.Info("fapi2host listening", "addr", addr, "issuer", issuer, "redirect_uri", redirectUri)
	return httpServer.ListenAndServeTLS("", "")
}

// fapiClient registers a client that complies with the high security profile.
func fapiClient(key *clientKey, redirectUri string) (*storage_models.Client, error) {
	client := storage_models.NewClient()
	client.ClientId = key.id
	client.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
	jwks, err := json.Marshal(key.jwks(false))
	if err != nil {
		return nil, err
	}
	client.Jwks = string(jwks)
	client.RequireDPoP = true
	client.AuthorizationCodeLifetime = 60
	client.RequireConsent = false
	client.AllowOfflineAccess = true
	client.RedirectUris = []string{redirectUri}
	client.AllowedScopes = []string{
		wicket.StandardScopesOpenId,
		wicket.StandardScopesProfile,
		wicket.StandardScopesEmail,
		wicket.StandardScopesOfflineAccess,
	}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCode); err != nil {
		return nil, err
	}
	return client, nil
}

// login signs the test user in and returns to the authorization request.
// It shows no form, so the suite's browser only follows redirects.
func login(options *config_options.WicketOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		returnUrl, ok := localReturnUrl(r, options.UserInteraction.LoginReturnUrlParameter)
		if !ok {
			http.Error(w, "missing or non-local return URL", http.StatusBadRequest)
			return
		}
		principal, err := models.NewLocalUser(models.WithLocalUserSubjectId(subjectId)).CreatePrincipal()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		svc := godi.GetRequired[auth.Service](hosting.ScopeFrom(r.Context()))
		if err := svc.SignIn(r, w, wicket.DefaultCookieAuthenticationScheme, principal, auth.NewProperties()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, returnUrl, http.StatusSeeOther)
	}
}

// localReturnUrl reads the return URL parameter and accepts only a local path;
// browsers treat "/\" like "//", so it is refused as well.
func localReturnUrl(r *http.Request, parameter string) (string, bool) {
	returnUrl := r.URL.Query().Get(parameter)
	return returnUrl, strings.HasPrefix(returnUrl, "/") && !strings.HasPrefix(returnUrl, "//") && !strings.HasPrefix(returnUrl, "/\\")
}

// consent grants every requested scope and returns to the authorization
// request. Requests for offline_access reach it even for clients that do not
// require consent.
func consent(options *config_options.WicketOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		returnUrl, ok := localReturnUrl(r, options.UserInteraction.ConsentReturnUrlParameter)
		if !ok {
			http.Error(w, "missing or non-local return URL", http.StatusBadRequest)
			return
		}
		interaction := godi.GetRequired[services.InteractionService](hosting.ScopeFrom(r.Context()))
		request, err := interaction.GetAuthorizationContext(r.Context(), returnUrl)
		if err != nil || request == nil || request.ValidatedResources == nil {
			http.Error(w, "no authorization request", http.StatusBadRequest)
			return
		}
		response := &messages.ConsentResponse{ScopesValuesConsented: request.ValidatedResources.RawScopeValues()}
		if err := interaction.GrantConsent(r.Context(), request, response, ""); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, returnUrl, http.StatusSeeOther)
	}
}

// errorPage shows the error wicket reports to the user.
func errorPage(options *config_options.WicketOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		interaction := godi.GetRequired[services.InteractionService](hosting.ScopeFrom(r.Context()))
		message, err := interaction.GetErrorContext(r.Context(), r.URL.Query().Get(options.UserInteraction.ErrorIdParameter))
		text := "unknown error"
		if err == nil && message != nil {
			text = message.Error + " " + message.ErrorDescription
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><title>Error</title><p id=\"error\">%s</p>", html.EscapeString(text))
	}
}

// serverSigningKey makes the ES256 key the server signs tokens with.
func serverSigningKey() ([]storage.SigningCredentialStore, []storage.ValidationKeysStore, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// The key set document names a key by its RFC 7638 thumbprint, so the
	// credential takes the same kid.
	point, err := raw.PublicKey.Bytes()
	if err != nil {
		return nil, nil, err
	}
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, b64(point[1:33]), b64(point[33:65]))
	sum := sha256.Sum256([]byte(canonical))
	credential, err := tokens.NewSigningCredentials(raw, tokens.WithAlgorithm("ES256"), tokens.WithKid(b64(sum[:])))
	if err != nil {
		return nil, nil, err
	}
	return []storage.SigningCredentialStore{storage_memory.NewMemorySigningCredentialStore(credential)},
		[]storage.ValidationKeysStore{storage_memory.NewMemoryValidationKeysStore([]*models.SecurityKeyInfo{
			{Key: &raw.PublicKey, SigningAlgorithm: credential.Algorithm},
		})}, nil
}

// selfSignedCertificate makes a P-256 certificate for the issuer's host.
func selfSignedCertificate(issuer string) (tls.Certificate, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: u.Hostname()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{u.Hostname()}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// writeSuiteConfig writes the configuration the suite's test plan takes. The
// resource is the userinfo endpoint, which accepts DPoP bound tokens.
func writeSuiteConfig(path, issuer, alias string, keys []*clientKey) error {
	clientConfig := func(k *clientKey) map[string]any {
		return map[string]any{"client_id": k.id, "scope": "openid profile email offline_access", "jwks": k.jwks(true)}
	}
	config := map[string]any{
		"alias":       alias,
		"description": "wicket high security profile",
		"server":      map[string]any{"discoveryUrl": issuer + "/.well-known/openid-configuration"},
		"client":      clientConfig(keys[0]),
		"client2":     clientConfig(keys[1]),
		"resource":    map[string]any{"resourceUrl": issuer + "/connect/userinfo"},
		"browser": []any{map[string]any{
			"comment": "the host signs the user in without a form and redirects back to the suite",
			"match":   issuer + "/connect/authorize*",
			// Both tasks are optional: a refused request ends on the
			// host's error page, which the suite records as it finds it.
			"tasks": []any{
				map[string]any{
					"task":     "Error page",
					"optional": true,
					"match":    issuer + wicket.UIConstantsDefaultRoutePathsError + "*",
					"commands": []any{[]any{"wait", "id", "error", 10}},
				},
				map[string]any{
					"task":     "Verify Complete",
					"optional": true,
					"match":    "*/test/a/" + alias + "/callback*",
					"commands": []any{[]any{"wait", "id", "submission_complete", 10}},
				},
			},
		}},
	}
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
