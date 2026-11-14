// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package certbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	// mtlsClientId authenticates with its self-signed certificate and asks
	// for certificate bound access tokens.
	mtlsClientId = "certbound.mtls"
	// boundClientId authenticates with a shared secret and asks for
	// certificate bound access tokens.
	boundClientId = "certbound.secret"
	// boundUpdatingClientId is boundClientId with access token claims
	// updated on refresh.
	boundUpdatingClientId = "certbound.secret.updating"
	// plainClientId authenticates with a shared secret and does not ask for
	// bound tokens.
	plainClientId = "certbound.plain"
	// referenceClientId receives reference access tokens bound to its
	// certificate.
	referenceClientId = "certbound.reference"
	// browserClientId and publicClientId register the flag in a way the
	// configuration validation refuses.
	browserClientId = "certbound.browser"
	publicClientId  = "certbound.public"
	// browserControlClientId and publicControlClientId are the same
	// registrations without the flag.
	browserControlClientId = "certbound.browser.control"
	publicControlClientId  = "certbound.public.control"

	sharedSecret = "secret"
	apiName      = "api1"
	scopeName    = "api"
	redirectUri  = "https://client.example/callback"
	userName     = "bob"
	subjectId    = "1"
	// certificateHeader carries the test client's certificate chain to the
	// injected certificate source: base64 DER values separated by commas,
	// leaf first. It exists only in these tests; wicket trusts no header.
	certificateHeader = "X-Test-Client-Certificates"
)

var serial atomic.Int64

func selfSignedCertificate(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// thumbprint is computed by the test itself, not by wicket.
func thumbprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// headerSource is the certificate source a host behind a TLS terminating
// proxy would inject; here it reads the test header.
type headerSource struct{}

func (headerSource) ClientCertificates(request *http.Request) []*x509.Certificate {
	raw := request.Header.Get(certificateHeader)
	if raw == "" {
		return nil
	}
	var certificates []*x509.Certificate
	for _, member := range strings.Split(raw, ",") {
		der, err := base64.StdEncoding.DecodeString(member)
		if err != nil {
			return nil
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil
		}
		certificates = append(certificates, certificate)
	}
	return certificates
}

type scene struct {
	t               *testing.T
	pipeline        *integration_common.WicketPipeline
	referenceTokens *storage_impl.ReferenceTokenStore
	// mtlsCertificate is the registered certificate of mtlsClientId.
	mtlsCertificate *x509.Certificate
	// a, b are two certificates any secret client may present.
	a, b *x509.Certificate
}

type sceneOptions struct {
	enable    bool
	mutualTls bool
}

func secretClient(id string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(sharedSecret)
	client.ClientSecrets = []*storage_models.Secret{secret}
	if err := client.SetAllowedGrantTypes([]string{
		wicket.GrantTypePassword,
		wicket.GrantTypeClientCredentials,
		wicket.GrantTypeAuthorizationCode,
	}); err != nil {
		panic(err)
	}
	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{wicket.StandardScopesOpenId, scopeName}
	client.RequirePkce = false
	client.RequireConsent = false
	client.RedirectUris = []string{redirectUri}
	return client
}

func newScene(t *testing.T, o sceneOptions) *scene {
	t.Helper()
	s := &scene{t: t, pipeline: integration_common.NewWicketPipeline()}
	s.mtlsCertificate = selfSignedCertificate(t, "mtls-client")
	s.a = selfSignedCertificate(t, "certificate-a")
	s.b = selfSignedCertificate(t, "certificate-b")

	s.referenceTokens = storage_impl.NewReferenceTokenStore()
	s.pipeline.Root.ServerConfig().SetReferenceTokenStore(s.referenceTokens)

	mtls := storage_models.NewClient()
	mtls.ClientId = mtlsClientId
	mtls.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
	mtls.Jwks = `{"keys":[{"kty":"EC","x5c":["` + base64.StdEncoding.EncodeToString(s.mtlsCertificate.Raw) + `"]}]}`
	mtls.TlsClientCertificateBoundAccessTokens = true
	_ = mtls.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
	mtls.AllowedScopes = []string{scopeName}

	bound := secretClient(boundClientId)
	bound.TlsClientCertificateBoundAccessTokens = true

	updating := secretClient(boundUpdatingClientId)
	updating.TlsClientCertificateBoundAccessTokens = true
	updating.UpdateAccessTokenClaimsOnRefresh = true

	reference := secretClient(referenceClientId)
	reference.TlsClientCertificateBoundAccessTokens = true
	reference.AccessTokenType = wicket.AccessTokenTypeReference

	browser := secretClient(browserClientId)
	browser.TlsClientCertificateBoundAccessTokens = true
	browser.AllowAccessTokensViaBrowser = true

	public := secretClient(publicClientId)
	public.TlsClientCertificateBoundAccessTokens = true
	public.RequireClientSecret = false

	browserControl := secretClient(browserControlClientId)
	browserControl.AllowAccessTokensViaBrowser = true

	publicControl := secretClient(publicControlClientId)
	publicControl.RequireClientSecret = false

	s.pipeline.Clients = append(s.pipeline.Clients, mtls, bound, updating, secretClient(plainClientId), reference, browser, public, browserControl, publicControl)

	s.pipeline.IdentityScopes = append(s.pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())
	api := storage_models.NewApiResource()
	api.Name = apiName
	apiSecret := storage_models.NewSecret()
	apiSecret.Value = utils.Sha256(sharedSecret)
	api.ApiSecrets = []*storage_models.Secret{apiSecret}
	api.Scopes = []string{scopeName}
	s.pipeline.ApiResources = append(s.pipeline.ApiResources, api)
	apiScope := storage_models.NewApiScope()
	apiScope.Name = scopeName
	s.pipeline.ApiScopes = append(s.pipeline.ApiScopes, apiScope)

	user := test.NewTestUser()
	user.SubjectId = subjectId
	user.Username = userName
	user.Password = userName
	s.pipeline.Users = append(s.pipeline.Users, user)

	godi.GetRequired[*config_options.WicketOptions](s.pipeline.Root).MutualTls.Enabled = o.mutualTls
	if o.enable {
		cfg := s.pipeline.Root.ServerConfig()
		cfg.EnableClientCertificateAuthentication(clientcert.Options{})
		cfg.SetClientCertificateSource(headerSource{})
	}
	s.pipeline.Initialize()
	t.Cleanup(s.pipeline.TestServer.Close)
	return s
}

type reply struct {
	status int
	body   string
	header http.Header
}

func (r reply) field(name string) string {
	var document map[string]any
	if err := json.Unmarshal([]byte(r.body), &document); err != nil {
		return ""
	}
	value, _ := document[name].(string)
	return value
}

func (r reply) document(t *testing.T) map[string]any {
	t.Helper()
	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &document), "body %s", r.body)
	return document
}

func withCertificates(request *http.Request, certificates []*x509.Certificate) {
	if len(certificates) == 0 {
		return
	}
	members := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		members = append(members, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	request.Header.Set(certificateHeader, strings.Join(members, ","))
}

func (s *scene) do(request *http.Request) reply {
	s.t.Helper()
	response, err := http.DefaultClient.Do(request)
	require.NoError(s.t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(s.t, err)
	return reply{status: response.StatusCode, body: string(body), header: response.Header}
}

func (s *scene) post(endpoint string, values url.Values, certificates ...*x509.Certificate) reply {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+endpoint, strings.NewReader(values.Encode()))
	require.NoError(s.t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withCertificates(request, certificates)
	return s.do(request)
}

func (s *scene) userInfo(token string, certificates ...*x509.Certificate) reply {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodGet, s.pipeline.TestServer.URL+integration_common.UserInfoEndpoint, nil)
	require.NoError(s.t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	withCertificates(request, certificates)
	return s.do(request)
}

func (s *scene) introspect(token string) map[string]any {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+integration_common.IntrospectionEndpoint,
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(s.t, err)
	request.SetBasicAuth(apiName, sharedSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r := s.do(request)
	require.Equal(s.t, http.StatusOK, r.status, "introspection: %s", r.body)
	return r.document(s.t)
}

func (s *scene) discovery() map[string]any {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodGet, s.pipeline.TestServer.URL+integration_common.DiscoveryEndpoint, nil)
	require.NoError(s.t, err)
	r := s.do(request)
	require.Equal(s.t, http.StatusOK, r.status)
	return r.document(s.t)
}

func passwordRequest(clientId string) url.Values {
	return url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientId},
		"client_secret": {sharedSecret},
		"scope":         {wicket.StandardScopesOpenId + " " + scopeName + " offline_access"},
		"username":      {userName},
		"password":      {userName},
	}
}

func refreshRequest(clientId string, refreshToken string) url.Values {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientId},
		"client_secret": {sharedSecret},
		"refresh_token": {refreshToken},
	}
}

func mustIssue(t *testing.T, name string, r reply) {
	t.Helper()
	require.Equalf(t, http.StatusOK, r.status, "%s: body %s", name, r.body)
	require.NotEmptyf(t, r.field("access_token"), "%s: body %s", name, r.body)
}

func mustBeInvalidClient(t *testing.T, name string, r reply) {
	t.Helper()
	require.Equalf(t, http.StatusBadRequest, r.status, "%s: body %s", name, r.body)
	require.Equalf(t, "invalid_client", r.field("error"), "%s: body %s", name, r.body)
	require.Emptyf(t, r.field("access_token"), "%s: body %s", name, r.body)
	require.Emptyf(t, r.field("error_description"), "%s: body %s", name, r.body)
}

// jwtClaims decodes the payload of a JWT without verifying it.
func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "not a JWT: %s", token)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(payload, &decoded))
	return decoded
}

// requireBoundTo asserts that claims carry exactly the confirmation of cert.
func requireBoundTo(t *testing.T, claims map[string]any, cert *x509.Certificate) {
	t.Helper()
	cnf, ok := claims["cnf"].(map[string]any)
	require.Truef(t, ok, "cnf = %v, want an object", claims["cnf"])
	require.Equal(t, map[string]any{"x5t#S256": thumbprint(cert)}, cnf)
}

// storeReference places a reference access token for bob issued to clientId
// with the given extra claims, the way wicket stores bound reference tokens.
func (s *scene) storeReference(t *testing.T, handle string, clientId string, confirmation string, extra ...*claimspkg.Claim) {
	t.Helper()
	token := &storage_models.Token{
		Issuer:          s.pipeline.TestServer.URL,
		Audiences:       []string{apiName},
		CreationTime:    time.Now().UTC(),
		Lifetime:        3600,
		Type:            wicket.TokenTypesAccessToken,
		ClientId:        clientId,
		AccessTokenType: wicket.AccessTokenTypeReference,
		Confirmation:    confirmation,
		Claims: append([]*claimspkg.Claim{
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue(subjectId)),
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesClientId), claimspkg.WithClaimValue(clientId)),
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesScope), claimspkg.WithClaimValue(wicket.StandardScopesOpenId)),
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesScope), claimspkg.WithClaimValue(scopeName)),
		}, extra...),
	}
	require.NoError(t, s.referenceTokens.StoreReferenceToken(context.Background(), handle, token))
}
