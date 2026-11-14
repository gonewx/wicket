// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hardening

import (
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

var (
	everyRequestObjectAlgorithm = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"}
	asymmetricAlgorithms        = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)

func listOf(value any) []string {
	values, _ := value.([]any)
	out := make([]string, 0, len(values))
	for _, item := range values {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// ---- asymmetric request objects ----

func checkRequestObjectsOff(t *testing.T, s *scene) {
	t.Helper()
	s.mustReachLogin("HS256", requestObjectClientId, s.signedRequestObject(requestObjectClientId, jwa.HS256(), s.keys.symmetricJwk(t), "sym"))
	s.mustReachLogin("RS256", requestObjectClientId, s.signedRequestObject(requestObjectClientId, jwa.RS256(), s.keys.rsa, "rsa"))
	// The default assembly accepts the disguised request object; that the
	// option refuses it therefore comes from stripping the symmetric keys.
	s.mustReachLogin("disguised HMAC under RS256", requestObjectClientId, s.disguisedRequestObject(requestObjectClientId))
	if got := listOf(s.discovery()[requestObjectAlgorithms]); !slices.Equal(got, everyRequestObjectAlgorithm) {
		t.Fatalf("%s = %v, want %v", requestObjectAlgorithms, got, everyRequestObjectAlgorithm)
	}
}

func checkRequestObjectsOn(t *testing.T, s *scene) {
	t.Helper()
	s.mustReachLogin("RS256", requestObjectClientId, s.signedRequestObject(requestObjectClientId, jwa.RS256(), s.keys.rsa, "rsa"))
	s.mustReachLogin("PS256", requestObjectClientId, s.signedRequestObject(requestObjectClientId, jwa.PS256(), s.keys.rsa, "rsa"))
	s.mustReachLogin("ES256", requestObjectClientId, s.signedRequestObject(requestObjectClientId, jwa.ES256(), s.keys.ec, "ec"))
	symmetric := s.keys.symmetricJwk(t)
	s.mustRefuseRequestObject("HS256", requestObjectClientId, s.signedRequestObject(requestObjectClientId, jwa.HS256(), symmetric, "sym"))
	s.mustRefuseRequestObject("HS384", requestObjectClientId, s.signedRequestObject(requestObjectClientId, jwa.HS384(), s.keys.symmetric, "sym"))
	s.mustRefuseRequestObject("HS512", requestObjectClientId, s.signedRequestObject(requestObjectClientId, jwa.HS512(), s.keys.symmetric, "sym"))
	s.mustRefuseRequestObject("disguised HMAC under RS256", requestObjectClientId, s.disguisedRequestObject(requestObjectClientId))
	s.mustRefuseRequestObject("alg none", requestObjectClientId, s.unsignedRequestObject(requestObjectClientId))
	s.mustRefuseRequestObject("unparsable header", requestObjectClientId, "bm90IGpzb24.e30.c2ln")
	s.mustRefuseRequestObject("no asymmetric key", symmetricOnlyClientId, s.disguisedRequestObject(symmetricOnlyClientId))
	if got := listOf(s.discovery()[requestObjectAlgorithms]); !slices.Equal(got, asymmetricAlgorithms) {
		t.Fatalf("%s = %v, want %v", requestObjectAlgorithms, got, asymmetricAlgorithms)
	}
}

// ---- client assertion algorithms ----

func checkAssertionAlgorithms(t *testing.T, s *scene) {
	t.Helper()
	// Without a list the server algorithms apply, as before.
	s.mustIssue("no list, ES256", s.token(s.assertionRequest(assertionClientId, "ES256")))
	s.mustIssue("no list, RS256", s.token(s.assertionRequest(assertionClientId, "RS256")))

	s.mustIssue("listed ES256", s.token(s.assertionRequest(restrictedClientId, "ES256")))
	before := s.registry.registers.Load()
	s.mustBeInvalidClient("unlisted RS256", s.token(s.assertionRequest(restrictedClientId, "RS256")))
	if after := s.registry.registers.Load(); after != before {
		t.Fatalf("an assertion with an unlisted algorithm registered its jti (%d -> %d)", before, after)
	}

	for _, clientId := range []string{misconfiguredSymmetric, misconfiguredOutside, misconfiguredEmptyValue} {
		s.mustBeInvalidClient(clientId, s.token(s.assertionRequest(clientId, "ES256")))
		if client, err := s.findClient(clientId); err == nil || client != nil {
			t.Fatalf("%s: client store lookup = %v, %v; want an error", clientId, client, err)
		}
	}
	s.mustBeInvalidClient(misconfiguredMethod, s.token(request{form: clientCredentials(nil), basic: misconfiguredMethod}))
	if client, err := s.findClient(misconfiguredMethod); err == nil || client != nil {
		t.Fatalf("%s: client store lookup = %v, %v; want an error", misconfiguredMethod, client, err)
	}
}

// ---- client_credentials authentication ----

func checkConfidentialClientsIssue(t *testing.T, s *scene) {
	t.Helper()
	s.mustIssue("confidential client", s.token(request{form: clientCredentials(nil), basic: secretClientId}))
	s.mustIssue("private_key_jwt client", s.token(s.assertionRequest(assertionClientId, "ES256")))
	s.mustIssue("tls client", s.token(request{form: clientCredentials(url.Values{"client_id": {tlsClientId}}), certificate: s.keys.certificate}))
}

func checkOtherGrantsUnaffected(t *testing.T, s *scene) {
	t.Helper()
	for _, grant := range []url.Values{
		{"grant_type": {"authorization_code"}, "code": {"unknown"}, "redirect_uri": {redirectUri}, "client_id": {publicClientId}},
		{"grant_type": {"refresh_token"}, "refresh_token": {"unknown"}, "client_id": {publicClientId}},
	} {
		r := s.token(request{form: grant})
		if r.field("error") == "invalid_client" || r.field("error") == "" {
			t.Fatalf("%s: status %d body %s; want a grant error, not a client error", grant.Get("grant_type"), r.status, r.body)
		}
	}
}

func checkClientCredentialsOff(t *testing.T, s *scene) {
	t.Helper()
	s.mustIssue("public client", s.token(request{form: clientCredentials(url.Values{"client_id": {publicClientId}})}))
	checkConfidentialClientsIssue(t, s)
}

func checkClientCredentialsOn(t *testing.T, s *scene) {
	t.Helper()
	s.mustBeInvalidClient("public client", s.token(request{form: clientCredentials(url.Values{"client_id": {publicClientId}})}))
	s.mustBeInvalidClient("public client with a secret", s.token(request{form: clientCredentials(url.Values{"client_id": {publicClientId}, "client_secret": {"anything"}})}))
	s.mustBeInvalidClient("grant type in the query string", s.token(request{
		form:  url.Values{"client_id": {publicClientId}, "scope": {scopeName}},
		query: "grant_type=client_credentials",
	}))
	checkConfidentialClientsIssue(t, s)
	checkOtherGrantsUnaffected(t, s)
}

// ---- tests ----

func TestDefaultAssemblyKeepsEveryBehavior(t *testing.T) {
	s := newScene(t, options{})
	checkRequestObjectsOff(t, s)
	checkClientCredentialsOff(t, s)
	checkAssertionAlgorithms(t, s)
}

func TestAsymmetricRequestObjectsAlone(t *testing.T) {
	s := newScene(t, options{asymmetricRequestObjects: true})
	checkRequestObjectsOn(t, s)
	checkClientCredentialsOff(t, s)
	checkAssertionAlgorithms(t, s)
}

func TestClientCredentialsAuthenticationAlone(t *testing.T) {
	s := newScene(t, options{clientCredentials: true})
	checkClientCredentialsOn(t, s)
	checkRequestObjectsOff(t, s)
	checkAssertionAlgorithms(t, s)
}

func TestEveryOptionTogether(t *testing.T) {
	s := newScene(t, options{asymmetricRequestObjects: true, clientCredentials: true})
	checkRequestObjectsOn(t, s)
	checkClientCredentialsOn(t, s)
	checkAssertionAlgorithms(t, s)
}

func TestClientCredentialsRuleWrapsOnlyTheTokenEndpoint(t *testing.T) {
	s := newScene(t, options{clientCredentials: true})
	post := func(endpoint string, values url.Values) reply {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+endpoint, strings.NewReader(values.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return reply{status: response.StatusCode, body: string(body)}
	}
	revocation := post("/connect/revocation", url.Values{"client_id": {publicClientId}, "token": {"unknown"}, "grant_type": {"client_credentials"}})
	if revocation.status != http.StatusOK {
		t.Fatalf("revocation: status %d body %s; want the public client served as before", revocation.status, revocation.body)
	}
	device := post("/connect/deviceauthorization", url.Values{"client_id": {publicClientId}, "scope": {scopeName}, "grant_type": {"client_credentials"}})
	if device.field("error") == "invalid_client" {
		t.Fatalf("device authorization: status %d body %s; the rule must not apply", device.status, device.body)
	}
}
