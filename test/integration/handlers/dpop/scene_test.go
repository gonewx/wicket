// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	wicket_dpop "github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/replay"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	// secretClientId is a confidential client; its refresh tokens are not
	// bound to a proof key.
	secretClientId = "dpop.secret"
	// referenceClientId is a confidential client receiving reference access
	// tokens.
	referenceClientId = "dpop.reference"
	// publicClientId is a public client; its refresh tokens are bound to
	// the proof key they were issued with.
	publicClientId = "dpop.public"
	// requiredClientId has to present a proof.
	requiredClientId = "dpop.required"
	// requiredBrowserClientId has to present a proof but receives access
	// tokens via the browser, which configuration validation refuses.
	requiredBrowserClientId = "dpop.required.browser"
	// certificateClientId asks for certificate bound access tokens.
	certificateClientId = "dpop.certificate"

	sharedSecret = "secret"
	apiName      = "api1"
	scopeName    = "api"
	redirectUri  = "https://client.example/callback"
	userName     = "bob"
	subjectId    = "1"
	// certificateHeader carries the test client's certificate to the
	// injected certificate source. It exists only in these tests.
	certificateHeader = "X-Test-Client-Certificate"
)

// countingRegistry counts Register calls and the keys registered, and passes
// them to an in-memory registry.
type countingRegistry struct {
	inner     replay.Registry
	registers atomic.Int64
	mu        sync.Mutex
	keys      []string
}

func newCountingRegistry() *countingRegistry {
	return &countingRegistry{inner: replay.NewMemoryRegistry()}
}

func (r *countingRegistry) Register(ctx context.Context, key string, expiresAt time.Time) error {
	r.registers.Add(1)
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
	return r.inner.Register(ctx, key, expiresAt)
}

func (r *countingRegistry) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return r.inner.RemoveExpired(ctx, cutoff)
}

// failingRegistry fails every Register call with err.
type failingRegistry struct{ err error }

func (r failingRegistry) Register(context.Context, string, time.Time) error { return r.err }

func (r failingRegistry) RemoveExpired(context.Context, time.Time) (int, error) { return 0, nil }

// proofKey is a key the test client signs proofs with.
type proofKey struct {
	private *ecdsa.PrivateKey
}

func newProofKey(t *testing.T) proofKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return proofKey{private: key}
}

func encode(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func (k proofKey) coordinates() (string, string) {
	x := make([]byte, 32)
	y := make([]byte, 32)
	k.private.X.FillBytes(x)
	k.private.Y.FillBytes(y)
	return encode(x), encode(y)
}

func (k proofKey) jwk() map[string]any {
	x, y := k.coordinates()
	return map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}
}

// thumbprint is computed by the test itself from the canonical JSON of the
// required members (RFC 7638), not by wicket.
func (k proofKey) thumbprint() string {
	x, y := k.coordinates()
	digest := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return encode(digest[:])
}

// signWith builds an ES256 compact JWS over header and claims with signer.
func signWith(t *testing.T, signer *ecdsa.PrivateKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	rawHeader, err := json.Marshal(header)
	require.NoError(t, err)
	rawClaims, err := json.Marshal(claims)
	require.NoError(t, err)
	input := encode(rawHeader) + "." + encode(rawClaims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, signer, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + encode(signature)
}

var proofSequence atomic.Int64

// proofSpec describes one proof; zero fields take valid values.
type proofSpec struct {
	jti      string
	htm      string
	htu      string
	iat      time.Time
	typ      string
	alg      string
	signer   *ecdsa.PrivateKey
	withoutJ bool
	extra    map[string]any
	// headers overrides protected header members; a nil value removes one.
	headers map[string]any
}

type scene struct {
	t               *testing.T
	pipeline        *integration_common.WicketPipeline
	referenceTokens *storage_impl.ReferenceTokenStore
	registry        *countingRegistry
	certificate     *x509.Certificate
}

type sceneOptions struct {
	// enable declares DPoP enabled.
	enable bool
	// registry replaces the counting registry.
	registry replay.Registry
	// mutualTls also enables mutual TLS client authentication.
	mutualTls bool
}

func client(id string) *storage_models.Client {
	c := storage_models.NewClient()
	c.ClientId = id
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(sharedSecret)
	c.ClientSecrets = []*storage_models.Secret{secret}
	if err := c.SetAllowedGrantTypes([]string{
		wicket.GrantTypePassword,
		wicket.GrantTypeClientCredentials,
		wicket.GrantTypeAuthorizationCode,
	}); err != nil {
		panic(err)
	}
	c.AllowOfflineAccess = true
	c.AllowedScopes = []string{wicket.StandardScopesOpenId, scopeName}
	c.RequirePkce = false
	c.RequireConsent = false
	c.RedirectUris = []string{redirectUri}
	return c
}

// headerSource reads the test client certificate from certificateHeader.
type headerSource struct{}

func (headerSource) ClientCertificates(request *http.Request) []*x509.Certificate {
	raw := request.Header.Get(certificateHeader)
	if raw == "" {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return []*x509.Certificate{certificate}
}

func selfSignedCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dpop-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

func newScene(t *testing.T, o sceneOptions) *scene {
	t.Helper()
	s := &scene{t: t, pipeline: integration_common.NewWicketPipeline(), registry: newCountingRegistry()}

	s.referenceTokens = storage_impl.NewReferenceTokenStore()
	s.pipeline.Root.ServerConfig().SetReferenceTokenStore(s.referenceTokens)

	reference := client(referenceClientId)
	reference.AccessTokenType = wicket.AccessTokenTypeReference

	public := client(publicClientId)
	public.RequireClientSecret = false

	required := client(requiredClientId)
	required.RequireDPoP = true

	requiredBrowser := client(requiredBrowserClientId)
	requiredBrowser.RequireDPoP = true
	requiredBrowser.AllowAccessTokensViaBrowser = true

	certificate := client(certificateClientId)
	certificate.TlsClientCertificateBoundAccessTokens = true

	s.pipeline.Clients = append(s.pipeline.Clients, client(secretClientId), reference, public, required, requiredBrowser, certificate)

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

	cfg := s.pipeline.Root.ServerConfig()
	if o.registry != nil {
		cfg.SetReplayRegistry(o.registry)
	} else {
		cfg.SetReplayRegistry(s.registry)
	}
	if o.enable {
		cfg.EnableDPoP(wicket_dpop.Options{SigningAlgorithms: []string{"ES256", "PS256"}})
	}
	if o.mutualTls {
		s.certificate = selfSignedCertificate(t)
		godi.GetRequired[*config_options.WicketOptions](s.pipeline.Root).MutualTls.Enabled = true
		cfg.EnableClientCertificateAuthentication(clientcert.Options{})
		cfg.SetClientCertificateSource(headerSource{})
	}
	s.pipeline.Initialize()
	t.Cleanup(s.pipeline.TestServer.Close)
	return s
}

func (s *scene) tokenEndpoint() string {
	return s.pipeline.TestServer.URL + integration_common.TokenEndpoint
}

// proof signs a proof for the token endpoint with key, as spec says.
func (s *scene) proof(key proofKey, spec proofSpec) string {
	s.t.Helper()
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk()}
	if spec.typ != "" {
		header["typ"] = spec.typ
	}
	if spec.alg != "" {
		header["alg"] = spec.alg
	}
	if spec.withoutJ {
		delete(header, "jwk")
	}
	for name, value := range spec.headers {
		if value == nil {
			delete(header, name)
		} else {
			header[name] = value
		}
	}
	claims := map[string]any{
		"jti": spec.jti,
		"htm": http.MethodPost,
		"htu": s.tokenEndpoint(),
		"iat": time.Now().Unix(),
	}
	if spec.jti == "" {
		claims["jti"] = "proof-" + big.NewInt(proofSequence.Add(1)).String()
	}
	if spec.htm != "" {
		claims["htm"] = spec.htm
	}
	if spec.htu != "" {
		claims["htu"] = spec.htu
	}
	if !spec.iat.IsZero() {
		claims["iat"] = spec.iat.Unix()
	}
	for name, value := range spec.extra {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}
	signer := key.private
	if spec.signer != nil {
		signer = spec.signer
	}
	return signWith(s.t, signer, header, claims)
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

// token posts values to the token endpoint with one DPoP header field per
// proof.
func (s *scene) token(values url.Values, proofs ...string) reply {
	s.t.Helper()
	return s.tokenAt(s.tokenEndpoint(), values, proofs...)
}

func (s *scene) tokenAt(endpoint string, values url.Values, proofs ...string) reply {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	require.NoError(s.t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, proof := range proofs {
		request.Header.Add(wicket.DPoPHeaderName, proof)
	}
	if s.certificate != nil {
		request.Header.Set(certificateHeader, base64.StdEncoding.EncodeToString(s.certificate.Raw))
	}
	return s.do(request)
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

func (s *scene) introspect(token string) map[string]any {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+integration_common.IntrospectionEndpoint,
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(s.t, err)
	request.SetBasicAuth(apiName, sharedSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r := s.do(request)
	require.Equal(s.t, http.StatusOK, r.status, "introspection: %s", r.body)
	var document map[string]any
	require.NoError(s.t, json.Unmarshal([]byte(r.body), &document))
	return document
}

func (s *scene) discovery() map[string]any {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodGet, s.pipeline.TestServer.URL+integration_common.DiscoveryEndpoint, nil)
	require.NoError(s.t, err)
	r := s.do(request)
	require.Equal(s.t, http.StatusOK, r.status)
	var document map[string]any
	require.NoError(s.t, json.Unmarshal([]byte(r.body), &document))
	return document
}

// authorizationCode runs the authorize endpoint for clientId and returns the
// issued code.
func (s *scene) authorizationCode(clientId string) string {
	s.t.Helper()
	require.NoError(s.t, s.pipeline.Login(subjectId))
	authorization := s.pipeline.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "code",
		Scope:        wicket.StandardScopesOpenId + " " + scopeName + " offline_access",
		RedirectUri:  redirectUri,
		State:        "state",
		Nonce:        "nonce",
	})
	require.NotNil(s.t, authorization)
	require.NotEmpty(s.t, authorization.Code())
	return authorization.Code()
}

func passwordRequest(clientId string) url.Values {
	values := url.Values{
		"grant_type": {wicket.GrantTypePassword},
		"client_id":  {clientId},
		"scope":      {wicket.StandardScopesOpenId + " " + scopeName + " offline_access"},
		"username":   {userName},
		"password":   {userName},
	}
	if clientId != publicClientId {
		values.Set("client_secret", sharedSecret)
	}
	return values
}

func refreshRequest(clientId string, refreshToken string) url.Values {
	values := url.Values{
		"grant_type":    {wicket.GrantTypeRefreshToken},
		"client_id":     {clientId},
		"refresh_token": {refreshToken},
	}
	if clientId != publicClientId {
		values.Set("client_secret", sharedSecret)
	}
	return values
}

func codeRequest(clientId string, code string) url.Values {
	return url.Values{
		"grant_type":    {wicket.GrantTypeAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {redirectUri},
		"client_id":     {clientId},
		"client_secret": {sharedSecret},
	}
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

// confirmationOf returns the cnf object of claims, or nil.
func confirmationOf(claims map[string]any) map[string]any {
	cnf, _ := claims["cnf"].(map[string]any)
	return cnf
}

// storedConfirmation returns the cnf claim of the stored copy of a
// reference token, or nil.
func (s *scene) storedConfirmation(handle string) map[string]any {
	s.t.Helper()
	stored, err := s.referenceTokens.GetReferenceToken(context.Background(), handle)
	require.NoError(s.t, err)
	for _, claim := range stored.Claims {
		if claim.Type != wicket.JwtClaimTypesConfirmation {
			continue
		}
		cnf, ok := claim.Value.(map[string]any)
		require.Truef(s.t, ok, "stored cnf claim %T", claim.Value)
		return cnf
	}
	return nil
}

// requireIssued asserts a token response and that token_type is DPoP
// exactly when the access token carries cnf.jkt, read from the JWT itself
// or, for a reference token, from introspection. It returns the cnf object.
func (s *scene) requireIssued(name string, r reply, reference bool) map[string]any {
	s.t.Helper()
	require.Equalf(s.t, http.StatusOK, r.status, "%s: body %s", name, r.body)
	accessToken := r.field("access_token")
	require.NotEmptyf(s.t, accessToken, "%s: body %s", name, r.body)
	var cnf map[string]any
	if reference {
		require.Lenf(s.t, strings.Split(accessToken, "."), 1, "%s: reference token expected", name)
		cnf = s.storedConfirmation(accessToken)
		introspection := s.introspect(accessToken)
		require.Equalf(s.t, true, introspection["active"], "%s: %v", name, introspection)
	} else {
		cnf = confirmationOf(jwtClaims(s.t, accessToken))
	}
	_, bound := cnf["jkt"]
	tokenType := r.field("token_type")
	if bound {
		require.Equalf(s.t, wicket.TokenResponseTypesDPoP, tokenType, "%s: cnf %v", name, cnf)
	} else {
		require.Equalf(s.t, "Bearer", tokenType, "%s: cnf %v", name, cnf)
	}
	return cnf
}

func requireError(t *testing.T, name string, r reply, code string) {
	t.Helper()
	require.Equalf(t, http.StatusBadRequest, r.status, "%s: body %s", name, r.body)
	require.Equalf(t, code, r.field("error"), "%s: body %s", name, r.body)
	require.Emptyf(t, r.field("access_token"), "%s: body %s", name, r.body)
}

func requireFixedServerError(t *testing.T, name string, r reply) {
	t.Helper()
	require.Equalf(t, http.StatusInternalServerError, r.status, "%s: body %q", name, r.body)
	require.Equalf(t, "Internal Server Error\n", r.body, "%s", name)
	require.Equalf(t, "no-store", r.header.Get("Cache-Control"), "%s", name)
	require.Truef(t, strings.HasPrefix(r.header.Get("Content-Type"), "text/plain"), "%s: %s", name, r.header.Get("Content-Type"))
}
