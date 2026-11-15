// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package highsecurity covers the high security profile end to end: its
// assembly requirements, the client conflicts it rejects, the constraints it
// enforces on the PAR, authorize and token flow, and the discovery document.
package highsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/replay"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	fapiClient   = "fapi.client"
	sharedClient = "shared.client"
	sharedSecret = "secret"
)

func encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func redirectUriOf(clientId string) string { return "https://" + clientId + "/callback" }

var sequence atomic.Int64

func nextId(prefix string) string { return fmt.Sprintf("%s-%d", prefix, sequence.Add(1)) }

// ecKey is a P-256 key signing ES256 compact JWS.
type ecKey struct{ private *ecdsa.PrivateKey }

func newKey(t *testing.T) ecKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ecKey{private: key}
}

func (k ecKey) jwk() map[string]any {
	x := make([]byte, 32)
	y := make([]byte, 32)
	k.private.X.FillBytes(x)
	k.private.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "crv": "P-256", "x": encode(x), "y": encode(y)}
}

func (k ecKey) keySet(kid string) string {
	jwk := k.jwk()
	jwk["kid"] = kid
	raw, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return string(raw)
}

func (k ecKey) sign(t *testing.T, header map[string]any, claims map[string]any) string {
	t.Helper()
	rawHeader, _ := json.Marshal(header)
	rawClaims, _ := json.Marshal(claims)
	input := encode(rawHeader) + "." + encode(rawClaims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + encode(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

// compliantClient complies with the high security profile: private_key_jwt,
// DPoP, S256 PKCE, a 60 second code and an https redirect URI.
func compliantClient(clientId string, assertionKey ecKey) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = clientId
	client.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
	client.Jwks = assertionKey.keySet("k1")
	client.RequireDPoP = true
	client.AuthorizationCodeLifetime = 60
	client.RequireConsent = false
	client.RedirectUris = []string{redirectUriOf(clientId)}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCodeAndClientCredentials); err != nil {
		panic(err)
	}
	return client
}

// sharedSecretClient authenticates with a shared secret only, which the
// profile does not accept.
func sharedSecretClient() *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = sharedClient
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(sharedSecret)
	client.ClientSecrets = []*storage_models.Secret{secret}
	client.RequireDPoP = true
	client.AuthorizationCodeLifetime = 60
	client.RedirectUris = []string{redirectUriOf(sharedClient)}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCodeAndClientCredentials); err != nil {
		panic(err)
	}
	return client
}

type scene struct {
	t            *testing.T
	pipeline     *integration_common.WicketPipeline
	assertionKey ecKey
	proofKey     ecKey
	issuer       string
}

type sceneOptions struct {
	// profileOff leaves the profile disabled while every feature stays on.
	profileOff bool
	// clients replaces the static client list.
	clients func(assertionKey ecKey) []*storage_models.Client
	// injected serves the clients from an injected client store.
	injected bool
	// configure runs after the features are declared, before Freeze.
	configure func(*integration_common.WicketPipeline)
}

// prepare builds the pipeline with pushed authorization, DPoP and
// private_key_jwt enabled and, unless told otherwise, the profile.
func prepare(t *testing.T, o sceneOptions) *scene {
	t.Helper()
	s := &scene{t: t, pipeline: integration_common.NewWicketPipeline(), assertionKey: newKey(t), proofKey: newKey(t)}
	clients := []*storage_models.Client{compliantClient(fapiClient, s.assertionKey)}
	if o.clients != nil {
		clients = o.clients(s.assertionKey)
	}
	if o.injected {
		store, err := storage_memory.NewMemoryClientStore(clients)
		if err != nil {
			t.Fatal(err)
		}
		s.pipeline.ClientStore = store
	} else {
		s.pipeline.Clients = clients
	}
	s.pipeline.IdentityScopes = append(s.pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())
	user := test.NewTestUser()
	user.SubjectId = "bob"
	user.Username = "bob"
	s.pipeline.Users = append(s.pipeline.Users, user)

	cfg := s.pipeline.Root.ServerConfig()
	if !o.profileOff {
		cfg.EnableHighSecurityProfile()
	}
	cfg.SetPushedAuthorizationRequestStore(storage_memory.NewMemoryPushedAuthorizationRequestStore())
	cfg.SetPushedAuthorizationDataProtectionProvider(integration_common.NewPushedAuthorizationProtection())
	cfg.EnablePushedAuthorizationRequests(pushedauth.Options{})
	cfg.SetReplayRegistry(replay.NewMemoryRegistry())
	cfg.EnableDPoP(dpop.Options{})
	cfg.EnablePrivateKeyJwt(clientassertion.Options{})
	if o.configure != nil {
		o.configure(s.pipeline)
	}
	return s
}

func newScene(t *testing.T, o sceneOptions) *scene {
	t.Helper()
	s := prepare(t, o)
	s.pipeline.Initialize()
	s.pipeline.BrowserClient.AllowAutoRedirect = false
	t.Cleanup(s.pipeline.TestServer.Close)
	s.issuer, _ = s.discovery()["issuer"].(string)
	if s.issuer == "" {
		t.Fatal("no issuer")
	}
	return s
}

// initializePanic returns the panic text of assembling the scene.
func initializePanic(t *testing.T, o sceneOptions) (text string) {
	t.Helper()
	s := prepare(t, o)
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("assembly succeeded")
		}
		text = fmt.Sprint(recovered)
		if s.pipeline.TestServer != nil {
			s.pipeline.TestServer.Close()
		}
	}()
	s.pipeline.Initialize()
	return ""
}

type reply struct {
	status int
	header http.Header
	body   map[string]any
}

func (r reply) field(name string) string {
	value, _ := r.body[name].(string)
	return value
}

func (s *scene) client() *http.Client {
	return &http.Client{
		Transport:     s.pipeline.TestServer.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (s *scene) post(path string, values url.Values, header http.Header) reply {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+path, strings.NewReader(values.Encode()))
	if err != nil {
		s.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, list := range header {
		for _, value := range list {
			request.Header.Add(name, value)
		}
	}
	response, err := s.client().Do(request)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	r := reply{status: response.StatusCode, header: response.Header}
	_ = json.Unmarshal(raw, &r.body)
	return r
}

func (s *scene) discovery() map[string]any {
	s.t.Helper()
	response, err := s.client().Get(s.pipeline.TestServer.URL + integration_common.DiscoveryEndpoint)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	var document map[string]any
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		s.t.Fatal(err)
	}
	return document
}

// authenticate adds the private_key_jwt credentials of clientId to values.
func (s *scene) authenticate(clientId string, values url.Values) url.Values {
	s.t.Helper()
	values.Set(wicket.AuthorizeRequestClientId, clientId)
	values.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	values.Set("client_assertion", s.assertionKey.sign(s.t,
		map[string]any{"alg": "ES256", "kid": "k1", "typ": "client-authentication+jwt"},
		map[string]any{
			"iss": clientId, "sub": clientId, "aud": s.issuer,
			"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "jti": nextId("assertion"),
		}))
	return values
}

const codeVerifier = "a-code-verifier-of-at-least-forty-three-characters-long-0123456789"

func codeChallenge() string {
	digest := sha256.Sum256([]byte(codeVerifier))
	return encode(digest[:])
}

func authorizationParameters(clientId string) url.Values {
	return url.Values{
		wicket.AuthorizeRequestResponseType:        {wicket.ResponseTypesCode},
		wicket.AuthorizeRequestScope:               {wicket.StandardScopesOpenId},
		wicket.AuthorizeRequestRedirectUri:         {redirectUriOf(clientId)},
		wicket.AuthorizeRequestState:               {"state"},
		wicket.AuthorizeRequestNonce:               {"nonce"},
		wicket.AuthorizeRequestCodeChallenge:       {codeChallenge()},
		wicket.AuthorizeRequestCodeChallengeMethod: {wicket.CodeChallengeMethodsSha256},
	}
}

func (s *scene) push(values url.Values) reply {
	s.t.Helper()
	return s.post("/"+wicket.ProtocolRoutePathsPushedAuthorization, values, nil)
}

// browse requests target with the signed-in browser, following no redirect.
func (s *scene) browse(target string) (int, *url.URL) {
	s.t.Helper()
	response, err := s.pipeline.BrowserClient.Get(target)
	if err != nil {
		s.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	location, _ := url.Parse(response.Header.Get("Location"))
	return response.StatusCode, location
}

func (s *scene) authorizeUrl(query url.Values) string {
	return s.pipeline.TestServer.URL + "/" + wicket.ProtocolRoutePathsAuthorize + "?" + query.Encode()
}

func (s *scene) proof() string {
	return s.proofKey.sign(s.t,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": s.proofKey.jwk()},
		map[string]any{"jti": nextId("proof"), "htm": http.MethodPost, "htu": s.pipeline.TestServer.URL + integration_common.TokenEndpoint, "iat": time.Now().Unix()})
}

func (s *scene) login() {
	s.t.Helper()
	if err := s.pipeline.Login("bob"); err != nil {
		s.t.Fatal(err)
	}
}

// TestHighSecurityProfileFlow pushes, authorizes and redeems with a
// compliant client and checks every constraint the flow passes through.
func TestHighSecurityProfileFlow(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	s.login()

	t.Run("authorization request without PAR is refused", func(t *testing.T) {
		query := authorizationParameters(fapiClient)
		query.Set(wicket.AuthorizeRequestClientId, fapiClient)
		status, location := s.browse(s.authorizeUrl(query))
		if status != http.StatusSeeOther || location == nil || location.Path != integration_common.ErrorPage {
			t.Fatalf("status %d location %v, want 303 to the error page", status, location)
		}
		s.pipeline.ErrorMessage = nil
		s.browse(location.String())
		message := s.pipeline.ErrorMessage
		if message == nil || message.Error != "invalid_request" || !strings.Contains(message.ErrorDescription, "pushed authorization request") {
			t.Fatalf("error page shows %+v", message)
		}
	})
	t.Run("PAR without redirect_uri is refused", func(t *testing.T) {
		values := authorizationParameters(fapiClient)
		values.Del(wicket.AuthorizeRequestRedirectUri)
		r := s.push(s.authenticate(fapiClient, values))
		if r.status != http.StatusBadRequest || r.field("error") != "invalid_request" {
			t.Fatalf("status %d body %v", r.status, r.body)
		}
	})
	t.Run("PAR with a symmetric request object is refused", func(t *testing.T) {
		header, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "oauth-authz-req+jwt"})
		claims, _ := json.Marshal(map[string]any{
			"iss": fapiClient, "aud": s.issuer, "client_id": fapiClient,
			"response_type": "code", "scope": "openid", "redirect_uri": redirectUriOf(fapiClient),
			"code_challenge": codeChallenge(), "code_challenge_method": "S256",
			"exp": time.Now().Add(time.Minute).Unix(),
		})
		input := encode(header) + "." + encode(claims)
		mac := hmac.New(sha256.New, []byte("a-shared-key-of-thirty-two-bytes!!"))
		mac.Write([]byte(input))
		values := s.authenticate(fapiClient, url.Values{wicket.AuthorizeRequestRequest: {input + "." + encode(mac.Sum(nil))}})
		r := s.push(values)
		if r.status != http.StatusBadRequest {
			t.Fatalf("status %d body %v", r.status, r.body)
		}
	})
	t.Run("compliant flow", func(t *testing.T) {
		r := s.push(s.authenticate(fapiClient, authorizationParameters(fapiClient)))
		if r.status != http.StatusCreated {
			t.Fatalf("push: status %d body %v", r.status, r.body)
		}
		status, location := s.browse(s.authorizeUrl(url.Values{
			wicket.AuthorizeRequestClientId:   {fapiClient},
			wicket.AuthorizeRequestRequestUri: {r.field("request_uri")},
		}))
		if status != http.StatusSeeOther {
			t.Fatalf("authorize answered %d, want 303", status)
		}
		code := location.Query().Get("code")
		if code == "" || !strings.HasPrefix(location.String(), redirectUriOf(fapiClient)) {
			t.Fatalf("authorize redirected to %v", location)
		}
		if location.Query().Get("iss") != s.issuer {
			t.Fatalf("iss %q, want %q", location.Query().Get("iss"), s.issuer)
		}
		token := s.post(integration_common.TokenEndpoint, s.authenticate(fapiClient, url.Values{
			"grant_type":    {wicket.GrantTypeAuthorizationCode},
			"code":          {code},
			"redirect_uri":  {redirectUriOf(fapiClient)},
			"code_verifier": {codeVerifier},
		}), http.Header{wicket.DPoPHeaderName: {s.proof()}})
		if token.status != http.StatusOK || !strings.EqualFold(token.field("token_type"), "DPoP") {
			t.Fatalf("token: status %d body %v", token.status, token.body)
		}
	})
}

// TestHighSecurityProfileRefusesConflictingInjectedClients serves clients
// that conflict with the profile from an injected store: they are invalid
// clients at the token and PAR endpoints.
func TestHighSecurityProfileRefusesConflictingInjectedClients(t *testing.T) {
	t.Parallel()
	conflicts := map[string]func(*storage_models.Client){
		"shared secret": func(*storage_models.Client) {},
		"plain PKCE":    func(c *storage_models.Client) { c.AllowPlainTextPkce = true },
		"no PKCE":       func(c *storage_models.Client) { c.RequirePkce = false },
		"public client": func(c *storage_models.Client) {
			c.RequireClientSecret = false
			c.ClientSecrets = nil
		},
	}
	for name, conflict := range conflicts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newScene(t, sceneOptions{injected: true, clients: func(assertionKey ecKey) []*storage_models.Client {
				client := sharedSecretClient()
				if name != "shared secret" {
					// Every other conflict is tested on an otherwise
					// compliant client, except the public client which
					// cannot use private_key_jwt.
					if name != "public client" {
						client = compliantClient(sharedClient, assertionKey)
					}
				}
				conflict(client)
				return []*storage_models.Client{compliantClient(fapiClient, assertionKey), client}
			}})
			credentials := func(values url.Values) (url.Values, http.Header) {
				switch name {
				case "shared secret":
					header := http.Header{}
					request := &http.Request{Header: header}
					request.SetBasicAuth(sharedClient, sharedSecret)
					return values, header
				case "public client":
					values.Set(wicket.AuthorizeRequestClientId, sharedClient)
					return values, http.Header{}
				default:
					return s.authenticate(sharedClient, values), http.Header{}
				}
			}
			values, header := credentials(url.Values{"grant_type": {wicket.GrantTypeClientCredentials}})
			header.Set(wicket.DPoPHeaderName, s.proof())
			if r := s.post(integration_common.TokenEndpoint, values, header); r.status != http.StatusBadRequest && r.status != http.StatusUnauthorized || r.field("error") != "invalid_client" {
				t.Fatalf("token: status %d body %v", r.status, r.body)
			}
			values, header = credentials(authorizationParameters(sharedClient))
			if r := s.post("/"+wicket.ProtocolRoutePathsPushedAuthorization, values, header); r.status == http.StatusCreated || r.field("error") != "invalid_client" {
				t.Fatalf("push: status %d body %v", r.status, r.body)
			}
			// The compliant client of the same store is served.
			if r := s.push(s.authenticate(fapiClient, authorizationParameters(fapiClient))); r.status != http.StatusCreated {
				t.Fatalf("compliant push: status %d body %v", r.status, r.body)
			}
		})
	}
}

// TestHighSecurityProfileRequiresClientCredentialsAuthentication sends an
// unauthenticated client_credentials request for a client that requires no
// secret, without RequireClientCredentialsAuthentication being declared. A
// client the profile accepts registers private_key_jwt or a tls method, whose
// authenticator already refuses a request without credentials, so this reply
// does not isolate the client_credentials tightening; the di unit tests
// assert that ClientCredentialsAuthenticationRequired follows the profile.
func TestHighSecurityProfileRequiresClientCredentialsAuthentication(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{clients: func(assertionKey ecKey) []*storage_models.Client {
		client := compliantClient(sharedClient, assertionKey)
		client.RequireClientSecret = false
		if err := client.SetAllowedGrantTypes(wicket.GrantTypesClientCredentials); err != nil {
			panic(err)
		}
		return []*storage_models.Client{compliantClient(fapiClient, assertionKey), client}
	}})
	r := s.post(integration_common.TokenEndpoint, url.Values{
		"grant_type": {wicket.GrantTypeClientCredentials},
		"client_id":  {sharedClient},
	}, http.Header{wicket.DPoPHeaderName: {s.proof()}})
	if r.status != http.StatusBadRequest || r.field("error") != "invalid_client" {
		t.Fatalf("token: status %d body %v", r.status, r.body)
	}
}

// TestHighSecurityProfileAssemblyRequirements fails assembly when a
// prerequisite is missing or a static client conflicts.
func TestHighSecurityProfileAssemblyRequirements(t *testing.T) {
	t.Parallel()
	t.Run("PAR and sender constraint missing", func(t *testing.T) {
		t.Parallel()
		pipeline := integration_common.NewWicketPipeline()
		pipeline.Root.ServerConfig().EnableHighSecurityProfile()
		var text string
		func() {
			defer func() { text = fmt.Sprint(recover()) }()
			pipeline.Initialize()
		}()
		for _, want := range []string{"pushed authorization requests are not enabled", "no sender constraint is enabled", "no asymmetric client authentication is enabled"} {
			if !strings.Contains(text, want) {
				t.Fatalf("panic %q lacks %q", text, want)
			}
		}
	})
	t.Run("static client with a shared secret", func(t *testing.T) {
		t.Parallel()
		text := initializePanic(t, sceneOptions{clients: func(assertionKey ecKey) []*storage_models.Client {
			return []*storage_models.Client{compliantClient(fapiClient, assertionKey), sharedSecretClient()}
		}})
		if !strings.Contains(text, `client "shared.client" conflicts with the profile: token endpoint authentication method`) || strings.Contains(text, fapiClient) {
			t.Fatalf("panic %q", text)
		}
	})
	t.Run("private_key_jwt with RS256 only", func(t *testing.T) {
		t.Parallel()
		text := initializePanic(t, sceneOptions{configure: func(p *integration_common.WicketPipeline) {
			p.Root.ServerConfig().EnablePrivateKeyJwt(clientassertion.Options{SigningAlgorithms: []string{"RS256"}})
		}})
		if !strings.Contains(text, "private_key_jwt accepts neither PS256 nor ES256") {
			t.Fatalf("panic %q", text)
		}
	})
}

// narrowedDiscoveryKeys are the discovery entries the profile narrows.
var narrowedDiscoveryKeys = []string{
	wicket.DiscoveryRequirePushedAuthorizationRequests,
	wicket.DiscoveryCodeChallengeMethodsSupported,
	wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported,
	wicket.DiscoveryResponseTypesSupported,
	wicket.DiscoveryGrantTypesSupported,
	wicket.DiscoveryAuthorizationResponseIssParameterSupported,
	wicket.DiscoveryTokenEndpointAuthSigningAlgorithmsSupported,
	wicket.DiscoveryDPoPSigningAlgValuesSupported,
	wicket.DiscoveryRequestObjectSigningAlgorithmsSupported,
}

func strings_(value any) []string {
	var out []string
	list, _ := value.([]any)
	for _, entry := range list {
		if text, ok := entry.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// TestHighSecurityProfileDiscovery compares the document of the same
// assembly with the profile on and off: only the narrowed entries differ,
// each only by removed values, and they advertise the effective
// constraints. The authorization server metadata is the same document.
func TestHighSecurityProfileDiscovery(t *testing.T) {
	t.Parallel()
	off := newScene(t, sceneOptions{profileOff: true}).discovery()
	onScene := newScene(t, sceneOptions{})
	on := onScene.discovery()

	offKeys := make([]string, 0, len(off))
	for key := range off {
		offKeys = append(offKeys, key)
	}
	onKeys := make([]string, 0, len(on))
	for key := range on {
		onKeys = append(onKeys, key)
	}
	slices.Sort(offKeys)
	slices.Sort(onKeys)
	if !slices.Equal(offKeys, onKeys) {
		t.Fatalf("keys differ:\noff %v\non  %v", offKeys, onKeys)
	}
	for key, value := range off {
		if slices.Contains(narrowedDiscoveryKeys, key) {
			if list := strings_(on[key]); list != nil {
				for _, entry := range list {
					if !slices.Contains(strings_(value), entry) {
						t.Fatalf("%s advertises %q, which the profile does not narrow from %v", key, entry, value)
					}
				}
			}
			continue
		}
		if key == wicket.DiscoveryIssuer || strings.HasSuffix(key, "_endpoint") || key == wicket.DiscoveryJwksUri || key == wicket.DiscoveryCheckSessionIframe || key == wicket.DiscoveryMtlsEndpointAliases {
			continue // the two scenes run on different test servers
		}
		if !reflect.DeepEqual(value, on[key]) {
			t.Fatalf("%s differs: off %v, on %v", key, value, on[key])
		}
	}

	if off[wicket.DiscoveryRequirePushedAuthorizationRequests] != false || on[wicket.DiscoveryRequirePushedAuthorizationRequests] != true {
		t.Fatalf("require_pushed_authorization_requests off %v on %v", off[wicket.DiscoveryRequirePushedAuthorizationRequests], on[wicket.DiscoveryRequirePushedAuthorizationRequests])
	}
	expect := map[string][]string{
		wicket.DiscoveryCodeChallengeMethodsSupported:               {"S256"},
		wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported: {"private_key_jwt"},
		wicket.DiscoveryResponseTypesSupported:                      {"code"},
		wicket.DiscoveryTokenEndpointAuthSigningAlgorithmsSupported: {"PS256", "ES256"},
		wicket.DiscoveryDPoPSigningAlgValuesSupported:               {"PS256", "ES256"},
	}
	for key, want := range expect {
		if got := strings_(on[key]); !slices.Equal(got, want) {
			t.Fatalf("%s = %v, want %v", key, got, want)
		}
	}
	if !slices.Contains(strings_(off[wicket.DiscoveryCodeChallengeMethodsSupported]), "plain") {
		t.Fatalf("baseline code_challenge_methods_supported %v", off[wicket.DiscoveryCodeChallengeMethodsSupported])
	}
	grants := strings_(on[wicket.DiscoveryGrantTypesSupported])
	if slices.Contains(grants, wicket.GrantTypePassword) || slices.Contains(grants, wicket.GrantTypeImplicit) || !slices.Contains(grants, wicket.GrantTypeAuthorizationCode) {
		t.Fatalf("grant_types_supported %v", grants)
	}
	if !slices.Contains(strings_(off[wicket.DiscoveryGrantTypesSupported]), wicket.GrantTypePassword) {
		t.Fatalf("baseline grant_types_supported %v", off[wicket.DiscoveryGrantTypesSupported])
	}
	if on[wicket.DiscoveryAuthorizationResponseIssParameterSupported] != true {
		t.Fatalf("authorization_response_iss_parameter_supported %v", on[wicket.DiscoveryAuthorizationResponseIssParameterSupported])
	}
	for _, algorithm := range strings_(on[wicket.DiscoveryRequestObjectSigningAlgorithmsSupported]) {
		if strings.HasPrefix(algorithm, "HS") || algorithm == "none" {
			t.Fatalf("request_object_signing_alg_values_supported advertises %s", algorithm)
		}
	}

	// With mutual TLS client authentication, both tls methods stay
	// advertised and no shared secret method remains.
	mtls := newScene(t, sceneOptions{configure: func(p *integration_common.WicketPipeline) {
		godi.GetRequired[*config_options.WicketOptions](p.Root).MutualTls.Enabled = true
		p.Root.ServerConfig().EnableClientCertificateAuthentication(clientcert.Options{TrustedAuthorities: x509.NewCertPool()})
	}}).discovery()
	methods := strings_(mtls[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported])
	for _, want := range []string{"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"} {
		if !slices.Contains(methods, want) {
			t.Fatalf("token_endpoint_auth_methods_supported %v lacks %s", methods, want)
		}
	}
	for _, method := range methods {
		if strings.HasPrefix(method, "client_secret_") {
			t.Fatalf("token_endpoint_auth_methods_supported %v keeps %s", methods, method)
		}
	}

	response, err := onScene.client().Get(onScene.pipeline.TestServer.URL + wicket.ProtocolRoutePathsAuthorizationServerMetadata)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var metadata map[string]any
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	for _, key := range narrowedDiscoveryKeys {
		if !reflect.DeepEqual(metadata[key], on[key]) {
			t.Fatalf("metadata %s = %v, discovery %v", key, metadata[key], on[key])
		}
	}
}
