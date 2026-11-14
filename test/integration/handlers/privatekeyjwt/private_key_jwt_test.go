// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package privatekeyjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/replay"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	assertionType     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	assertionClientId = "assertion-client"
	uriClientId       = "uri-client"
	secretClientId    = "secret-client"
	sharedSecret      = "secret"
	apiName           = "api1"
	scopeName         = "api"
	algorithmsKey     = "token_endpoint_auth_signing_alg_values_supported"
	methodsKey        = "token_endpoint_auth_methods_supported"
)

func encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// signingKey is an ES256 key generated for the test run.
type signingKey struct {
	kid     string
	private *ecdsa.PrivateKey
}

func newSigningKey(t *testing.T, kid string) signingKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return signingKey{kid: kid, private: private}
}

func (k signingKey) jwk(t *testing.T) string {
	t.Helper()
	point, err := k.private.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode point: %v", err)
	}
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","kid":%q,"x":%q,"y":%q}`, k.kid, encode(point[1:33]), encode(point[33:]))
}

func (k signingKey) keySet(t *testing.T) string { return `{"keys":[` + k.jwk(t) + `]}` }

func (k signingKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": k.kid, "typ": "client-authentication+jwt"})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	input := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return input + "." + encode(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
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

// failingRegistry is a registry double whose Register always fails.
type failingRegistry struct{ err error }

func (r failingRegistry) Register(context.Context, string, time.Time) error { return r.err }

func (r failingRegistry) RemoveExpired(context.Context, time.Time) (int, error) { return 0, nil }

// scene is one assembly behind a test server.
type scene struct {
	t        *testing.T
	pipeline *integration_common.WicketPipeline
	key      signingKey
	issuer   string
	sequence atomic.Int64
}

type sceneOptions struct {
	enable    bool
	options   clientassertion.Options
	registry  replay.Registry
	key       *signingKey
	jwksUri   string
	issuerUri string
	// customAlgorithms, when set, is written as the host's custom discovery
	// entry under the signing algorithms key.
	customAlgorithms []string
}

func newScene(t *testing.T, o sceneOptions) *scene {
	t.Helper()
	s := &scene{t: t, pipeline: integration_common.NewWicketPipeline()}
	if o.key != nil {
		s.key = *o.key
	} else {
		s.key = newSigningKey(t, "k1")
	}

	registered := storage_models.NewClient()
	registered.ClientId = assertionClientId
	registered.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
	registered.Jwks = s.key.keySet(t)
	// A secret is registered as well to show that it is not honoured.
	registeredSecret := storage_models.NewSecret()
	registeredSecret.Value = utils.Sha256(sharedSecret)
	registered.ClientSecrets = []*storage_models.Secret{registeredSecret}
	_ = registered.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials, wicket.GrantTypeDeviceCode})
	registered.AllowedScopes = []string{scopeName}

	shared := storage_models.NewClient()
	shared.ClientId = secretClientId
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(sharedSecret)
	shared.ClientSecrets = []*storage_models.Secret{secret}
	_ = shared.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
	shared.AllowedScopes = []string{scopeName}

	s.pipeline.Clients = []*storage_models.Client{registered, shared}
	if o.jwksUri != "" {
		byUri := storage_models.NewClient()
		byUri.ClientId = uriClientId
		byUri.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
		byUri.JwksUri = o.jwksUri
		_ = byUri.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
		byUri.AllowedScopes = []string{scopeName}
		s.pipeline.Clients = append(s.pipeline.Clients, byUri)
	}

	api := storage_models.NewApiResource()
	api.Name = apiName
	api.Enabled = true
	apiSecret := storage_models.NewSecret()
	apiSecret.Value = utils.Sha256(sharedSecret)
	apiKey := storage_models.NewSecret()
	apiKey.Type = wicket.SecretTypesJsonWebKey
	apiKey.Value = s.key.jwk(t)
	api.ApiSecrets = []*storage_models.Secret{apiSecret, apiKey}
	api.Scopes = []string{scopeName}
	s.pipeline.ApiResources = append(s.pipeline.ApiResources, api)
	scope := storage_models.NewApiScope()
	scope.Name = scopeName
	s.pipeline.ApiScopes = append(s.pipeline.ApiScopes, scope)

	// The declaration comes after the root is built and before Freeze, which
	// the pipeline calls while it initializes.
	cfg := s.pipeline.Root.ServerConfig()
	if o.registry != nil {
		cfg.SetReplayRegistry(o.registry)
	}
	if o.enable {
		cfg.EnablePrivateKeyJwt(o.options)
	}
	if o.issuerUri != "" {
		godi.GetRequired[*config_options.WicketOptions](s.pipeline.Root).IssuerUri = o.issuerUri
	}
	if o.customAlgorithms != nil {
		godi.GetRequired[*config_options.WicketOptions](s.pipeline.Root).Discovery.CustomEntries = map[string]any{
			algorithmsKey: o.customAlgorithms,
		}
	}
	s.pipeline.Initialize()
	t.Cleanup(s.pipeline.TestServer.Close)

	s.issuer, _ = s.discovery()["issuer"].(string)
	if s.issuer == "" {
		t.Fatalf("discovery document names no issuer")
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

// claims returns a valid claim set for id with a fresh jti.
func (s *scene) claims(id string) map[string]any {
	return map[string]any{
		"iss": id,
		"sub": id,
		"aud": s.issuer,
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": fmt.Sprintf("jti-%d-%d", time.Now().UnixNano(), s.sequence.Add(1)),
	}
}

func (s *scene) assertion(id string) string { return s.key.sign(s.t, s.claims(id)) }

type reply struct {
	status int
	header http.Header
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

func (s *scene) post(endpoint string, values url.Values) reply {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		s.t.Fatalf("request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		s.t.Fatalf("post %s: %v", endpoint, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		s.t.Fatalf("read %s: %v", endpoint, err)
	}
	return reply{status: response.StatusCode, header: response.Header, body: string(body)}
}

func withAssertion(assertion string, extra url.Values) url.Values {
	values := url.Values{"client_assertion_type": {assertionType}, "client_assertion": {assertion}}
	for name, value := range extra {
		values[name] = value
	}
	return values
}

func tokenRequest() url.Values {
	return url.Values{"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName}}
}

func (s *scene) tokenWith(assertion string) reply {
	return s.post(integration_common.TokenEndpoint, withAssertion(assertion, tokenRequest()))
}

func mustBeInvalidClient(t *testing.T, name string, r reply) {
	t.Helper()
	if r.field("error") != "invalid_client" || r.field("access_token") != "" {
		t.Fatalf("%s: status %d body %s, want invalid_client", name, r.status, r.body)
	}
	// The token error result of the endpoint always writes the description
	// member; for a failed client authentication it has to stay empty.
	if r.field("error_description") != "" || strings.Contains(r.body, "error_uri") {
		t.Fatalf("%s: failure carries a description: %s", name, r.body)
	}
}

func enabledScene(t *testing.T) (*scene, *countingRegistry) {
	registry := &countingRegistry{Registry: replay.NewMemoryRegistry()}
	return newScene(t, sceneOptions{enable: true, registry: registry}), registry
}

func TestValidAssertionAuthenticatesAtEveryEndpoint(t *testing.T) {
	s, registry := enabledScene(t)

	token := s.tokenWith(s.assertion(assertionClientId))
	accessToken := token.field("access_token")
	if token.status != http.StatusOK || accessToken == "" {
		t.Fatalf("token endpoint: status %d body %s", token.status, token.body)
	}

	// client_id may accompany the assertion when it names the same client.
	named := s.post(integration_common.TokenEndpoint, withAssertion(s.assertion(assertionClientId),
		url.Values{"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName}, "client_id": {assertionClientId}}))
	if named.status != http.StatusOK || named.field("access_token") == "" {
		t.Fatalf("token endpoint with client_id: status %d body %s", named.status, named.body)
	}

	revocation := s.post(integration_common.RevocationEndpoint, withAssertion(s.assertion(assertionClientId), url.Values{"token": {"unknown-token"}}))
	if revocation.status != http.StatusOK {
		t.Fatalf("revocation endpoint: status %d body %s", revocation.status, revocation.body)
	}

	device := s.post(integration_common.DeviceAuthorization, withAssertion(s.assertion(assertionClientId), url.Values{"scope": {scopeName}}))
	if device.status != http.StatusOK || device.field("device_code") == "" {
		t.Fatalf("device authorization endpoint: status %d body %s", device.status, device.body)
	}

	introspection := s.post(integration_common.IntrospectionEndpoint, withAssertion(s.assertion(apiName), url.Values{"token": {accessToken}}))
	if introspection.status != http.StatusOK || !strings.Contains(introspection.body, `"active":true`) {
		t.Fatalf("introspection endpoint: status %d body %s", introspection.status, introspection.body)
	}

	// The backchannel authentication endpoint authenticates the client first;
	// the request itself is incomplete here, so what follows the client
	// authentication is a request error and not invalid_client.
	before := registry.registers.Load()
	ciba := s.post(integration_common.BackchannelAuthenticationEndpoint, withAssertion(s.assertion(assertionClientId), url.Values{"scope": {"openid"}}))
	if ciba.field("error") == "" || ciba.field("error") == "invalid_client" {
		t.Fatalf("backchannel authentication endpoint: status %d body %s", ciba.status, ciba.body)
	}
	if registry.registers.Load() != before+1 {
		t.Fatalf("backchannel authentication endpoint did not register the assertion")
	}
	rejected := s.post(integration_common.BackchannelAuthenticationEndpoint, withAssertion("not-an-assertion", url.Values{"scope": {"openid"}}))
	if rejected.field("error") != "invalid_client" {
		t.Fatalf("backchannel authentication endpoint with a bad assertion: status %d body %s", rejected.status, rejected.body)
	}

	if got := registry.registers.Load(); got != 6 {
		t.Fatalf("registry saw %d registrations, want 6", got)
	}
}

func TestFailedAssertionsAreIndistinguishable(t *testing.T) {
	s, registry := enabledScene(t)

	expired := s.claims(assertionClientId)
	expired["exp"] = time.Now().Add(-10 * time.Minute).Unix()
	delete(expired, "iat")
	wrongAudience := s.claims(assertionClientId)
	wrongAudience["aud"] = s.pipeline.TestServer.URL + integration_common.TokenEndpoint
	wrongIssuer := s.claims(assertionClientId)
	wrongIssuer["iss"] = secretClientId

	symmetric := func() string {
		header, _ := json.Marshal(map[string]any{"alg": "HS256"})
		payload, _ := json.Marshal(s.claims(assertionClientId))
		input := encode(header) + "." + encode(payload)
		mac := hmac.New(sha256.New, []byte(s.key.keySet(t)))
		mac.Write([]byte(input))
		return input + "." + encode(mac.Sum(nil))
	}()
	unsigned := func() string {
		header, _ := json.Marshal(map[string]any{"alg": "none"})
		payload, _ := json.Marshal(s.claims(assertionClientId))
		return encode(header) + "." + encode(payload) + "."
	}()
	foreign := newSigningKey(t, "k1").sign(t, s.claims(assertionClientId))
	unknownKey := newSigningKey(t, "k9").sign(t, s.claims(assertionClientId))

	stateless := []struct {
		name      string
		assertion string
	}{
		{"expired", s.key.sign(t, expired)},
		{"audience is the token endpoint", s.key.sign(t, wrongAudience)},
		{"issuer", s.key.sign(t, wrongIssuer)},
		{"symmetric algorithm", symmetric},
		{"alg none", unsigned},
		{"signature", foreign},
		{"unknown kid", unknownKey},
	}
	var replies []reply
	for _, tc := range stateless {
		r := s.tokenWith(tc.assertion)
		mustBeInvalidClient(t, tc.name, r)
		replies = append(replies, r)
	}
	if got := registry.registers.Load(); got != 0 {
		t.Fatalf("registry saw %d registrations for stateless failures, want 0", got)
	}

	replayed := s.assertion(assertionClientId)
	if first := s.tokenWith(replayed); first.status != http.StatusOK {
		t.Fatalf("first use: status %d body %s", first.status, first.body)
	}
	second := s.tokenWith(replayed)
	mustBeInvalidClient(t, "replay", second)
	replies = append(replies, second)

	// The same assertion is spent for every endpoint.
	elsewhere := s.post(integration_common.RevocationEndpoint, withAssertion(replayed, url.Values{"token": {"unknown-token"}}))
	if elsewhere.status == http.StatusOK {
		t.Fatalf("replayed assertion accepted at the revocation endpoint")
	}

	for i, r := range replies[1:] {
		if r.status != replies[0].status || r.body != replies[0].body {
			t.Fatalf("failure %d differs: %d %q vs %d %q", i+1, r.status, r.body, replies[0].status, replies[0].body)
		}
	}
}

func TestKeyRotationRefreshesTheKeySetOnce(t *testing.T) {
	first := newSigningKey(t, "a")
	second := newSigningKey(t, "b")
	var requests atomic.Int64
	var mu sync.Mutex
	published := first.keySet(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write([]byte(published))
	}))
	t.Cleanup(server.Close)

	s := newScene(t, sceneOptions{
		enable:   true,
		registry: replay.NewMemoryRegistry(),
		jwksUri:  server.URL + "/jwks",
		options:  clientassertion.Options{HTTPClient: server.Client(), JwksMinRefreshInterval: time.Millisecond},
	})

	for i := 0; i < 2; i++ {
		if r := s.tokenWith(first.sign(t, s.claims(uriClientId))); r.status != http.StatusOK {
			t.Fatalf("first key, use %d: status %d body %s", i, r.status, r.body)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("key set requested %d times, want 1", got)
	}

	mu.Lock()
	published = second.keySet(t)
	mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	if r := s.tokenWith(second.sign(t, s.claims(uriClientId))); r.status != http.StatusOK {
		t.Fatalf("rotated key: status %d body %s", r.status, r.body)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("key set requested %d times after rotation, want 2", got)
	}
	mustBeInvalidClient(t, "retired key", s.tokenWith(first.sign(t, s.claims(uriClientId))))
}

func TestTwoAssembliesShareOneRegistry(t *testing.T) {
	const issuer = "https://shared-issuer.example"
	registry := replay.NewMemoryRegistry()
	key := newSigningKey(t, "k1")
	one := newScene(t, sceneOptions{enable: true, registry: registry, key: &key, issuerUri: issuer})
	two := newScene(t, sceneOptions{enable: true, registry: registry, key: &key, issuerUri: issuer})
	if one.issuer != issuer || two.issuer != issuer {
		t.Fatalf("issuers %q and %q, want %q", one.issuer, two.issuer, issuer)
	}
	if one.pipeline.Root == two.pipeline.Root {
		t.Fatalf("the two assemblies share a root")
	}

	assertion := one.assertion(assertionClientId)
	if r := one.tokenWith(assertion); r.status != http.StatusOK || r.field("access_token") == "" {
		t.Fatalf("first assembly: status %d body %s", r.status, r.body)
	}
	mustBeInvalidClient(t, "second assembly", two.tokenWith(assertion))

	if r := two.tokenWith(two.assertion(assertionClientId)); r.status != http.StatusOK {
		t.Fatalf("fresh assertion at the second assembly: status %d body %s", r.status, r.body)
	}
}

func TestRegistryFailureIsAFixedServerError(t *testing.T) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	marker := "boom-" + encode(random)
	s := newScene(t, sceneOptions{enable: true, registry: failingRegistry{err: errors.New(marker)}})

	requests := map[string]func() reply{
		"token": func() reply { return s.tokenWith(s.assertion(assertionClientId)) },
		"revocation": func() reply {
			return s.post(integration_common.RevocationEndpoint, withAssertion(s.assertion(assertionClientId), url.Values{"token": {"unknown-token"}}))
		},
		"device authorization": func() reply {
			return s.post(integration_common.DeviceAuthorization, withAssertion(s.assertion(assertionClientId), url.Values{"scope": {scopeName}}))
		},
		"backchannel authentication": func() reply {
			return s.post(integration_common.BackchannelAuthenticationEndpoint, withAssertion(s.assertion(assertionClientId), url.Values{"scope": {"openid"}}))
		},
		"introspection": func() reply {
			return s.post(integration_common.IntrospectionEndpoint, withAssertion(s.assertion(apiName), url.Values{"token": {"unknown-token"}}))
		},
	}
	for endpoint, send := range requests {
		r := send()
		if r.status != http.StatusInternalServerError {
			t.Fatalf("%s: status %d, want exactly 500 (body %q)", endpoint, r.status, r.body)
		}
		if r.body != "Internal Server Error\n" {
			t.Fatalf("%s: body %q", endpoint, r.body)
		}
		if got := r.header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s: Cache-Control %q", endpoint, got)
		}
		everything := r.body
		for name, values := range r.header {
			everything += "\n" + name + ": " + strings.Join(values, ",")
		}
		for _, forbidden := range []string{"invalid_client", marker, "access_token", "device_code"} {
			if strings.Contains(everything, forbidden) {
				t.Fatalf("%s: response carries %q: %s", endpoint, forbidden, everything)
			}
		}
	}

	// A client that authenticates with a shared secret does not touch the
	// registry and is served as usual.
	shared := s.post(integration_common.TokenEndpoint, url.Values{
		"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName},
		"client_id": {secretClientId}, "client_secret": {sharedSecret},
	})
	if shared.status != http.StatusOK || shared.field("access_token") == "" {
		t.Fatalf("shared secret client: status %d body %s", shared.status, shared.body)
	}
}

func TestAssertionAndSharedSecretSideBySide(t *testing.T) {
	s, registry := enabledScene(t)

	both := withAssertion(s.assertion(assertionClientId), tokenRequest())
	both.Set("client_id", assertionClientId)
	both.Set("client_secret", sharedSecret)
	mustBeInvalidClient(t, "assertion and client_secret", s.post(integration_common.TokenEndpoint, both))

	secretOnly := tokenRequest()
	secretOnly.Set("client_id", assertionClientId)
	secretOnly.Set("client_secret", sharedSecret)
	mustBeInvalidClient(t, "registered client with client_secret only", s.post(integration_common.TokenEndpoint, secretOnly))

	// A client that is not registered for the method cannot use an assertion.
	mustBeInvalidClient(t, "shared secret client with an assertion", s.tokenWith(s.assertion(secretClientId)))
	if got := registry.registers.Load(); got != 0 {
		t.Fatalf("registry saw %d registrations, want 0", got)
	}

	shared := tokenRequest()
	shared.Set("client_id", secretClientId)
	shared.Set("client_secret", sharedSecret)
	if r := s.post(integration_common.TokenEndpoint, shared); r.status != http.StatusOK || r.field("access_token") == "" {
		t.Fatalf("shared secret client: status %d body %s", r.status, r.body)
	}
}

func TestDiscoveryAdvertisesTheMethodOnlyWhenEnabled(t *testing.T) {
	configured := []string{"PS256", "ES256"}
	enabled := newScene(t, sceneOptions{enable: true, registry: replay.NewMemoryRegistry(),
		options: clientassertion.Options{SigningAlgorithms: configured}})
	document := enabled.discovery()
	if methods := stringList(document[methodsKey]); !slices.Contains(methods, "private_key_jwt") {
		t.Fatalf("%s = %v, want private_key_jwt listed", methodsKey, methods)
	}
	if algorithms := stringList(document[algorithmsKey]); !slices.Equal(algorithms, configured) {
		t.Fatalf("%s = %v, want %v", algorithmsKey, algorithms, configured)
	}

	plain := newScene(t, sceneOptions{})
	document = plain.discovery()
	methods := stringList(document[methodsKey])
	if slices.Contains(methods, "private_key_jwt") {
		t.Fatalf("%s lists private_key_jwt without the feature: %v", methodsKey, methods)
	}
	if !slices.Equal(methods, []string{"client_secret_basic", "client_secret_post"}) {
		t.Fatalf("%s = %v, want the two shared secret methods", methodsKey, methods)
	}
	if _, present := document[algorithmsKey]; present {
		t.Fatalf("%s advertised without the feature", algorithmsKey)
	}
}

func stringList(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func TestRegisteredClientIsRefusedWhileTheFeatureIsNotEnabled(t *testing.T) {
	s := newScene(t, sceneOptions{})

	secretOnly := tokenRequest()
	secretOnly.Set("client_id", assertionClientId)
	secretOnly.Set("client_secret", sharedSecret)
	mustBeInvalidClient(t, "registered client with client_secret", s.post(integration_common.TokenEndpoint, secretOnly))

	// Assertion parameters are not read by an assembly without the feature.
	mustBeInvalidClient(t, "registered client with an assertion", s.post(integration_common.TokenEndpoint,
		withAssertion(s.assertion(assertionClientId), url.Values{"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName}, "client_id": {assertionClientId}})))

	shared := tokenRequest()
	shared.Set("client_id", secretClientId)
	shared.Set("client_secret", sharedSecret)
	if r := s.post(integration_common.TokenEndpoint, shared); r.status != http.StatusOK || r.field("access_token") == "" {
		t.Fatalf("shared secret client: status %d body %s", r.status, r.body)
	}
}

func TestCustomDiscoveryEntryCannotAdvertiseSigningAlgorithms(t *testing.T) {
	plain := newScene(t, sceneOptions{customAlgorithms: []string{"HS256"}})
	if value, present := plain.discovery()[algorithmsKey]; present {
		t.Fatalf("%s advertised from a custom entry without the feature: %v", algorithmsKey, value)
	}

	configured := []string{"ES256"}
	enabled := newScene(t, sceneOptions{enable: true, registry: replay.NewMemoryRegistry(),
		options: clientassertion.Options{SigningAlgorithms: configured}, customAlgorithms: []string{"none", "HS256"}})
	if algorithms := stringList(enabled.discovery()[algorithmsKey]); !slices.Equal(algorithms, configured) {
		t.Fatalf("%s = %v, want %v", algorithmsKey, algorithms, configured)
	}
}
