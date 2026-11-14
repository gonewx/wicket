// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hardening

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	requestObjectClientId    = "ro-client"
	symmetricOnlyClientId    = "ro-symmetric-client"
	publicClientId           = "public-client"
	secretClientId           = "secret-client"
	assertionClientId        = "assertion-client"
	restrictedClientId       = "restricted-client"
	tlsClientId              = "tls-client"
	misconfiguredSymmetric   = "misconfigured-symmetric"
	misconfiguredMethod      = "misconfigured-method"
	misconfiguredOutside     = "misconfigured-outside"
	misconfiguredEmptyValue  = "misconfigured-empty"
	sharedSecret             = "secret"
	scopeName                = "api"
	redirectUri              = "https://client/callback"
	assertionType            = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	requestObjectAlgorithms  = "request_object_signing_alg_values_supported"
	certificateHeader        = "X-Test-Client-Certificates"
	invalidRequestObjectCode = "invalid_request_object"
)

// headerSource reads the test client's certificate from a header; it stands
// in for what a host behind a TLS terminating proxy would inject.
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

// countingRegistry forwards to a registry and counts Register calls.
type countingRegistry struct {
	replay.Registry
	registers atomic.Int64
}

func (r *countingRegistry) Register(ctx context.Context, key string, expiresAt time.Time) error {
	r.registers.Add(1)
	return r.Registry.Register(ctx, key, expiresAt)
}

// options selects the hardening options a scene declares.
type options struct {
	asymmetricRequestObjects bool
	clientCredentials        bool
}

// keys are the client keys of a scene, generated per test.
type keys struct {
	rsa         *rsa.PrivateKey
	ec          *ecdsa.PrivateKey
	symmetric   []byte
	certificate *x509.Certificate
}

type scene struct {
	t        *testing.T
	pipeline *integration_common.WicketPipeline
	keys     keys
	registry *countingRegistry
	issuer   string
	sequence atomic.Int64
}

func newKeys(t *testing.T) keys {
	t.Helper()
	var k keys
	var err error
	if k.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if k.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	k.symmetric = make([]byte, 64)
	if _, err = rand.Read(k.symmetric); err != nil {
		t.Fatal(err)
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: tlsClientId},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &certificateKey.PublicKey, certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	if k.certificate, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	return k
}

func publicJwk(t *testing.T, key any, kid string) jwk.Key {
	t.Helper()
	imported, err := jwk.Import(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.PublicKeyOf(imported)
	if err != nil {
		t.Fatal(err)
	}
	if err := public.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	return public
}

func (k keys) symmetricJwk(t *testing.T) jwk.Key {
	t.Helper()
	key, err := jwk.Import(k.symmetric)
	if err != nil {
		t.Fatal(err)
	}
	// The key names its own algorithm, as a registered symmetric JWK may.
	if err := key.Set(jwk.KeyIDKey, "sym"); err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.HS256()); err != nil {
		t.Fatal(err)
	}
	return key
}

func jsonText(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func jwkSecret(t *testing.T, key jwk.Key) *storage_models.Secret {
	t.Helper()
	secret := storage_models.NewSecret()
	secret.Type = wicket.SecretTypesJsonWebKey
	secret.Value = jsonText(t, key)
	return secret
}

func (k keys) assertionJwks(t *testing.T) string {
	t.Helper()
	return jsonText(t, map[string]any{"keys": []any{publicJwk(t, k.ec, "ec"), publicJwk(t, k.rsa, "rsa")}})
}

func newScene(t *testing.T, o options) *scene {
	t.Helper()
	s := &scene{
		t:        t,
		pipeline: integration_common.NewWicketPipeline(),
		keys:     newKeys(t),
		registry: &countingRegistry{Registry: replay.NewMemoryRegistry()},
	}

	requestObject := storage_models.NewClient()
	requestObject.ClientId = requestObjectClientId
	requestObject.RequireRequestObject = true
	requestObject.RedirectUris = []string{redirectUri}
	requestObject.ClientSecrets = []*storage_models.Secret{
		jwkSecret(t, s.keys.symmetricJwk(t)),
		jwkSecret(t, publicJwk(t, s.keys.rsa, "rsa")),
		jwkSecret(t, publicJwk(t, s.keys.ec, "ec")),
	}
	_ = requestObject.SetAllowedGrantTypes(wicket.GrantTypesImplicit)
	requestObject.AllowedScopes = []string{"openid", "profile"}

	symmetricOnly := storage_models.NewClient()
	symmetricOnly.ClientId = symmetricOnlyClientId
	symmetricOnly.RequireRequestObject = true
	symmetricOnly.RedirectUris = []string{redirectUri}
	symmetricOnly.ClientSecrets = []*storage_models.Secret{jwkSecret(t, s.keys.symmetricJwk(t))}
	_ = symmetricOnly.SetAllowedGrantTypes(wicket.GrantTypesImplicit)
	symmetricOnly.AllowedScopes = []string{"openid", "profile"}

	public := storage_models.NewClient()
	public.ClientId = publicClientId
	public.RequireClientSecret = false
	public.RedirectUris = []string{redirectUri}
	_ = public.SetAllowedGrantTypes([]string{wicket.GrantTypeAuthorizationCode, wicket.GrantTypeClientCredentials})
	public.AllowedScopes = []string{scopeName}

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(sharedSecret)
	confidential := storage_models.NewClient()
	confidential.ClientId = secretClientId
	confidential.ClientSecrets = []*storage_models.Secret{secret}
	_ = confidential.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
	confidential.AllowedScopes = []string{scopeName}

	assertionClient := func(id string, algorithms []string) *storage_models.Client {
		client := storage_models.NewClient()
		client.ClientId = id
		// No secret is required: the assertion alone authenticates.
		client.RequireClientSecret = false
		client.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
		client.Jwks = s.keys.assertionJwks(t)
		client.TokenEndpointAuthSigningAlgorithms = algorithms
		_ = client.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
		client.AllowedScopes = []string{scopeName}
		return client
	}

	tls := storage_models.NewClient()
	tls.ClientId = tlsClientId
	tls.RequireClientSecret = false
	tls.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
	tls.Jwks = `{"keys":[{"kty":"EC","x5c":["` + base64.StdEncoding.EncodeToString(s.keys.certificate.Raw) + `"]}]}`
	_ = tls.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
	tls.AllowedScopes = []string{scopeName}

	wrongMethodSecret := storage_models.NewSecret()
	wrongMethodSecret.Value = utils.Sha256(sharedSecret)
	wrongMethod := storage_models.NewClient()
	wrongMethod.ClientId = misconfiguredMethod
	wrongMethod.ClientSecrets = []*storage_models.Secret{wrongMethodSecret}
	wrongMethod.TokenEndpointAuthSigningAlgorithms = []string{"ES256"}
	_ = wrongMethod.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
	wrongMethod.AllowedScopes = []string{scopeName}

	s.pipeline.Clients = []*storage_models.Client{
		requestObject, symmetricOnly, public, confidential, tls, wrongMethod,
		assertionClient(assertionClientId, nil),
		assertionClient(restrictedClientId, []string{"ES256"}),
		assertionClient(misconfiguredSymmetric, []string{"HS256"}),
		assertionClient(misconfiguredOutside, []string{"ES256", "PS256"}),
		assertionClient(misconfiguredEmptyValue, []string{""}),
	}

	api := storage_models.NewApiResource()
	api.Name = "api1"
	api.Enabled = true
	api.Scopes = []string{scopeName}
	s.pipeline.ApiResources = append(s.pipeline.ApiResources, api)
	scope := storage_models.NewApiScope()
	scope.Name = scopeName
	s.pipeline.ApiScopes = append(s.pipeline.ApiScopes, scope)
	s.pipeline.IdentityScopes = append(s.pipeline.IdentityScopes,
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesProfile(),
	)

	// Every option is declared after the root is built and before Freeze,
	// which the pipeline calls while it initializes.
	cfg := s.pipeline.Root.ServerConfig()
	cfg.SetReplayRegistry(s.registry)
	cfg.EnablePrivateKeyJwt(clientassertion.Options{SigningAlgorithms: []string{"RS256", "ES256"}})
	cfg.EnableClientCertificateAuthentication(clientcert.Options{})
	cfg.SetClientCertificateSource(headerSource{})
	if o.asymmetricRequestObjects {
		cfg.RequireAsymmetricRequestObjects()
	}
	if o.clientCredentials {
		cfg.RequireClientCredentialsAuthentication()
	}
	godi.GetRequired[*config_options.WicketOptions](s.pipeline.Root).Endpoints.EnableJwtRequestUri = true
	s.pipeline.Initialize()
	t.Cleanup(s.pipeline.TestServer.Close)

	s.issuer, _ = s.discovery()["issuer"].(string)
	if s.issuer == "" {
		t.Fatal("discovery document names no issuer")
	}
	return s
}

func (s *scene) discovery() map[string]any {
	s.t.Helper()
	response, err := http.Get(s.pipeline.TestServer.URL + integration_common.DiscoveryEndpoint)
	if err != nil {
		s.t.Fatalf("discovery: %v", err)
	}
	defer response.Body.Close()
	var document map[string]any
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		s.t.Fatalf("decode discovery: %v", err)
	}
	return document
}

// ---- request objects ----

func (s *scene) requestClaims(clientId string) map[string]any {
	return map[string]any{
		"iss":           clientId,
		"aud":           s.pipeline.TestServer.URL,
		"exp":           time.Now().Add(time.Minute).Unix(),
		"client_id":     clientId,
		"response_type": "id_token",
		"scope":         "openid profile",
		"state":         "state",
		"nonce":         "nonce",
		"redirect_uri":  redirectUri,
	}
}

// signedRequestObject signs the request object of clientId with key under
// algorithm; kid names the registered key.
func (s *scene) signedRequestObject(clientId string, algorithm jwa.SignatureAlgorithm, key any, kid string) string {
	s.t.Helper()
	token := jwt.New()
	for name, value := range s.requestClaims(clientId) {
		if err := token.Set(name, value); err != nil {
			s.t.Fatal(err)
		}
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.KeyIDKey, kid)
	signed, err := jwt.Sign(token, jwt.WithKey(algorithm, key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		s.t.Fatal(err)
	}
	return string(signed)
}

func segment(t *testing.T, value any) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(jsonText(t, value)))
}

// disguisedRequestObject declares RS256 but carries an HMAC SHA-256
// signature made with the client's registered symmetric key.
func (s *scene) disguisedRequestObject(clientId string) string {
	s.t.Helper()
	input := segment(s.t, map[string]any{"alg": "RS256", "kid": "sym"}) + "." + segment(s.t, s.requestClaims(clientId))
	mac := hmac.New(sha256.New, s.keys.symmetric)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *scene) unsignedRequestObject(clientId string) string {
	s.t.Helper()
	return segment(s.t, map[string]any{"alg": "none"}) + "." + segment(s.t, s.requestClaims(clientId)) + "."
}

// authorize sends the request object by value, or by reference when byUri
// is set, and reports whether the login page was reached and the error code
// otherwise.
func (s *scene) authorize(clientId string, requestObject string, byUri bool) (bool, string) {
	s.t.Helper()
	extra := url.Values{}
	if byUri {
		objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(requestObject))
		}))
		defer objectServer.Close()
		extra.Set("request_uri", objectServer.URL+"/request.jwt")
	} else {
		extra.Set("request", requestObject)
	}
	routePath, err := s.pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "id_token",
		Extra:        extra,
	})
	if err != nil {
		s.t.Fatal(err)
	}
	s.pipeline.LoginRequest = nil
	s.pipeline.ErrorMessage = nil
	if _, err := s.pipeline.BrowserClient.Get(routePath.String()); err != nil {
		s.t.Fatal(err)
	}
	code := ""
	if s.pipeline.ErrorMessage != nil {
		code = s.pipeline.ErrorMessage.Error
	}
	return s.pipeline.LoginRequest != nil, code
}

func (s *scene) mustReachLogin(name string, clientId string, requestObject string) {
	s.t.Helper()
	for _, byUri := range []bool{false, true} {
		if reached, code := s.authorize(clientId, requestObject, byUri); !reached || code != "" {
			s.t.Fatalf("%s (request_uri %v): login reached %v, error %q; want the login page", name, byUri, reached, code)
		}
	}
}

func (s *scene) mustRefuseRequestObject(name string, clientId string, requestObject string) {
	s.t.Helper()
	for _, byUri := range []bool{false, true} {
		if reached, code := s.authorize(clientId, requestObject, byUri); reached || code != invalidRequestObjectCode {
			s.t.Fatalf("%s (request_uri %v): login reached %v, error %q; want %s", name, byUri, reached, code, invalidRequestObjectCode)
		}
	}
}

// ---- token endpoint ----

type reply struct {
	status int
	body   string
}

func (r reply) field(name string) string {
	var document map[string]any
	if err := json.Unmarshal([]byte(r.body), &document); err != nil {
		return ""
	}
	value, _ := document[name].(string)
	return value
}

type request struct {
	form        url.Values
	query       string
	basic       string
	certificate *x509.Certificate
}

func (s *scene) token(r request) reply {
	s.t.Helper()
	target := s.pipeline.TestServer.URL + integration_common.TokenEndpoint
	if r.query != "" {
		target += "?" + r.query
	}
	httpRequest, err := http.NewRequest(http.MethodPost, target, strings.NewReader(r.form.Encode()))
	if err != nil {
		s.t.Fatal(err)
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r.basic != "" {
		httpRequest.SetBasicAuth(r.basic, sharedSecret)
	}
	if r.certificate != nil {
		httpRequest.Header.Set(certificateHeader, base64.StdEncoding.EncodeToString(r.certificate.Raw))
	}
	response, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	return reply{status: response.StatusCode, body: string(body)}
}

func clientCredentials(extra url.Values) url.Values {
	values := url.Values{"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName}}
	for name, value := range extra {
		values[name] = value
	}
	return values
}

func (s *scene) assertionClaims(clientId string) map[string]any {
	return map[string]any{
		"iss": clientId,
		"sub": clientId,
		"aud": s.issuer,
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": fmt.Sprintf("jti-%d-%d", time.Now().UnixNano(), s.sequence.Add(1)),
	}
}

// assertion signs a client assertion of clientId with ES256 or RS256.
func (s *scene) assertion(clientId string, algorithm string) string {
	s.t.Helper()
	kid := map[string]string{"ES256": "ec", "RS256": "rsa"}[algorithm]
	input := segment(s.t, map[string]any{"alg": algorithm, "kid": kid}) + "." + segment(s.t, s.assertionClaims(clientId))
	digest := sha256.Sum256([]byte(input))
	var signature []byte
	switch algorithm {
	case "ES256":
		r, sv, err := ecdsa.Sign(rand.Reader, s.keys.ec, digest[:])
		if err != nil {
			s.t.Fatal(err)
		}
		signature = append(r.FillBytes(make([]byte, 32)), sv.FillBytes(make([]byte, 32))...)
	case "RS256":
		var err error
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.keys.rsa, crypto.SHA256, digest[:])
		if err != nil {
			s.t.Fatal(err)
		}
	default:
		s.t.Fatalf("unexpected algorithm %s", algorithm)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (s *scene) assertionRequest(clientId string, algorithm string) request {
	return request{form: clientCredentials(url.Values{
		"client_assertion_type": {assertionType},
		"client_assertion":      {s.assertion(clientId, algorithm)},
	})}
}

func (s *scene) mustIssue(name string, r reply) {
	s.t.Helper()
	if r.status != http.StatusOK || r.field("access_token") == "" {
		s.t.Fatalf("%s: status %d body %s; want a token", name, r.status, r.body)
	}
}

func (s *scene) mustBeInvalidClient(name string, r reply) {
	s.t.Helper()
	if r.status != http.StatusBadRequest || r.field("error") != "invalid_client" || r.field("access_token") != "" {
		s.t.Fatalf("%s: status %d body %s; want 400 invalid_client", name, r.status, r.body)
	}
	if r.field("error_description") != "" {
		s.t.Fatalf("%s: failure carries a description: %s", name, r.body)
	}
}

func (s *scene) findClient(clientId string) (*storage_models.Client, error) {
	return godi.GetRequired[storage.ClientStore](s.pipeline.Root).FindClientById(context.Background(), clientId)
}
