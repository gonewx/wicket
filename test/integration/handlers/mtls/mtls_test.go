// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package mtls

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func enabledScene(t *testing.T) *scene {
	return newScene(t, sceneOptions{enable: true, mutualTls: true})
}

func TestPkiCertificateAuthenticatesAtEveryClientEndpoint(t *testing.T) {
	s := enabledScene(t)
	chain := presented{certificates: []*x509.Certificate{s.leaf.cert}}

	mustIssueToken(t, "token endpoint", s.post(integration_common.TokenEndpoint, tokenRequest(pkiClientId, nil), chain))
	mustIssueToken(t, "mtls token alias", s.post("/"+wicket.ProtocolRoutePathsMtlsToken, tokenRequest(pkiClientId, nil), chain))

	for _, endpoint := range []string{integration_common.RevocationEndpoint, "/" + wicket.ProtocolRoutePathsMtlsRevocation} {
		r := s.post(endpoint, url.Values{"client_id": {pkiClientId}, "token": {"unknown-token"}}, chain)
		if r.status != http.StatusOK {
			t.Fatalf("revocation %s: status %d body %s", endpoint, r.status, r.body)
		}
	}
	for _, endpoint := range []string{integration_common.DeviceAuthorization, "/" + wicket.ProtocolRoutePathsMtlsDeviceAuthorization} {
		r := s.post(endpoint, url.Values{"client_id": {pkiClientId}, "scope": {scopeName}}, chain)
		if r.status != http.StatusOK || r.field("device_code") == "" {
			t.Fatalf("device authorization %s: status %d body %s", endpoint, r.status, r.body)
		}
	}

	// The backchannel authentication endpoint authenticates the client first;
	// the request itself is incomplete here, so what follows the client
	// authentication is a request error and not invalid_client.
	ciba := s.post(integration_common.BackchannelAuthenticationEndpoint, url.Values{"client_id": {pkiClientId}, "scope": {"openid"}}, chain)
	if ciba.field("error") == "" || ciba.field("error") == "invalid_client" {
		t.Fatalf("backchannel authentication endpoint: status %d body %s", ciba.status, ciba.body)
	}
	cibaWithout := s.post(integration_common.BackchannelAuthenticationEndpoint, url.Values{"client_id": {pkiClientId}, "scope": {"openid"}}, presented{})
	if cibaWithout.field("error") != "invalid_client" {
		t.Fatalf("backchannel authentication endpoint without certificate: status %d body %s", cibaWithout.status, cibaWithout.body)
	}
}

func TestSelfSignedCertificateAuthenticates(t *testing.T) {
	s := enabledScene(t)
	mustIssueToken(t, "self-signed", s.post(integration_common.TokenEndpoint, tokenRequest(selfClientId, nil),
		presented{certificates: []*x509.Certificate{s.selfSigned.cert}}))
	mustIssueToken(t, "self-signed at the alias", s.post("/"+wicket.ProtocolRoutePathsMtlsToken, tokenRequest(selfClientId, nil),
		presented{certificates: []*x509.Certificate{s.selfSigned.cert}}))
}

func TestFailedCertificateAuthenticationsAreIndistinguishable(t *testing.T) {
	s := enabledScene(t)

	foreignRoot := authority(t, "Foreign Root")
	untrusted := clientCertificate(t, "pki-client", &foreignRoot)
	otherSubject := clientCertificate(t, "someone-else", &s.root)
	otherSelfSigned := clientCertificate(t, "self-client", nil)

	cases := []struct {
		name     string
		clientId string
		extra    url.Values
		p        presented
	}{
		{"pki subject mismatch", pkiClientId, nil, presented{certificates: []*x509.Certificate{otherSubject.cert}}},
		{"pki untrusted chain", pkiClientId, nil, presented{certificates: []*x509.Certificate{untrusted.cert}}},
		{"pki no certificate", pkiClientId, nil, presented{}},
		{"pki secret only", pkiClientId, url.Values{"client_secret": {sharedSecret}}, presented{}},
		{"self-signed mismatch", selfClientId, nil, presented{certificates: []*x509.Certificate{otherSelfSigned.cert}}},
		{"self-signed no certificate", selfClientId, nil, presented{}},
		{"self-signed CA issued certificate", selfClientId, nil, presented{certificates: []*x509.Certificate{s.leaf.cert}}},
		{"certificate with client_secret", pkiClientId, url.Values{"client_secret": {sharedSecret}}, presented{certificates: []*x509.Certificate{s.leaf.cert}}},
		{"certificate with basic", pkiClientId, nil, presented{certificates: []*x509.Certificate{s.leaf.cert}, basic: true}},
		{"certificate with client_assertion", selfClientId, url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {"a.b.c"},
		}, presented{certificates: []*x509.Certificate{s.selfSigned.cert}}},
	}
	var first reply
	for i, tc := range cases {
		r := s.post(integration_common.TokenEndpoint, tokenRequest(tc.clientId, tc.extra), tc.p)
		mustBeInvalidClient(t, tc.name, r)
		if i == 0 {
			first = r
			continue
		}
		if tc.p.basic {
			// A request with an Authorization header is answered with a
			// challenge, which is a status and header difference only.
			if r.body != first.body {
				t.Fatalf("%s: body %q differs from %q", tc.name, r.body, first.body)
			}
			continue
		}
		if r.status != first.status || r.body != first.body {
			t.Fatalf("%s: status %d body %q differs from %d %q", tc.name, r.status, r.body, first.status, first.body)
		}
	}
}

func TestPkiMethodNeedsTrustedAuthorities(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, noRoots: true, mutualTls: true})
	// Without trusted authorities tls_client_auth is not available, so the
	// client registration does not validate and the client is unknown.
	mustBeInvalidClient(t, "pki without roots", s.post(integration_common.TokenEndpoint, tokenRequest(pkiClientId, nil),
		presented{certificates: []*x509.Certificate{s.leaf.cert}}))
	mustIssueToken(t, "self-signed without roots", s.post(integration_common.TokenEndpoint, tokenRequest(selfClientId, nil),
		presented{certificates: []*x509.Certificate{s.selfSigned.cert}}))

	methods := listOf(s.discovery()[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported])
	if slices.Contains(methods, wicket.EndpointAuthenticationMethodsTlsClientAuth) ||
		!slices.Contains(methods, wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth) {
		t.Fatalf("methods = %v, want only self_signed_tls_client_auth among the tls methods", methods)
	}
}

func TestOtherClientsAuthenticateAsBefore(t *testing.T) {
	enabled := enabledScene(t)
	baseline := newScene(t, sceneOptions{})

	for name, s := range map[string]*scene{"enabled": enabled, "baseline": baseline} {
		mustIssueToken(t, name+" secret client", s.post(integration_common.TokenEndpoint,
			tokenRequest(secretClientId, url.Values{"client_secret": {sharedSecret}}), presented{}))
		mustIssueToken(t, name+" secret client with a certificate", s.post(integration_common.TokenEndpoint,
			tokenRequest(secretClientId, url.Values{"client_secret": {sharedSecret}}), presented{certificates: []*x509.Certificate{enabled.leaf.cert}}))
		mustIssueToken(t, name+" secret client with basic", s.post(integration_common.TokenEndpoint,
			url.Values{"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName}, "client_id": {secretClientId}}, presented{basic: true}))
		mustBeInvalidClient(t, name+" secret client with a certificate only", s.post(integration_common.TokenEndpoint,
			tokenRequest(secretClientId, nil), presented{certificates: []*x509.Certificate{enabled.leaf.cert}}))
	}
	wrongEnabled := enabled.post(integration_common.TokenEndpoint, tokenRequest(secretClientId, url.Values{"client_secret": {"wrong"}}), presented{})
	wrongBaseline := baseline.post(integration_common.TokenEndpoint, tokenRequest(secretClientId, url.Values{"client_secret": {"wrong"}}), presented{})
	if wrongEnabled != wrongBaseline {
		t.Fatalf("wrong secret: enabled %+v, baseline %+v", wrongEnabled, wrongBaseline)
	}
}

func TestNotEnabledAssemblyServesNoMutualTls(t *testing.T) {
	s := newScene(t, sceneOptions{mutualTls: true})

	for _, path := range []string{
		wicket.ProtocolRoutePathsMtlsToken,
		wicket.ProtocolRoutePathsMtlsRevocation,
		wicket.ProtocolRoutePathsMtlsIntrospection,
		wicket.ProtocolRoutePathsMtlsDeviceAuthorization,
	} {
		r := s.post("/"+path, tokenRequest(secretClientId, url.Values{"client_secret": {sharedSecret}}), presented{})
		if r.status != http.StatusNotFound {
			t.Fatalf("alias %s: status %d body %s, want it not served", path, r.status, r.body)
		}
	}

	// Client registrations requiring a tls method do not validate.
	mustBeInvalidClient(t, "pki not enabled", s.post(integration_common.TokenEndpoint, tokenRequest(pkiClientId, nil),
		presented{certificates: []*x509.Certificate{s.leaf.cert}}))
	mustBeInvalidClient(t, "self-signed not enabled", s.post(integration_common.TokenEndpoint, tokenRequest(selfClientId, nil),
		presented{certificates: []*x509.Certificate{s.selfSigned.cert}}))

	document := s.discovery()
	for _, key := range []string{wicket.DiscoveryMtlsEndpointAliases, wicket.DiscoveryTlsClientCertificateBoundAccessTokens} {
		if _, ok := document[key]; ok {
			t.Fatalf("%s advertised by an assembly without mutual TLS client authentication", key)
		}
	}
	methods := listOf(document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported])
	if slices.Contains(methods, wicket.EndpointAuthenticationMethodsTlsClientAuth) ||
		slices.Contains(methods, wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth) {
		t.Fatalf("methods = %v advertise a tls method", methods)
	}
}

func TestEnabledWithoutMutualTlsIsNotAdvertised(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	// Authentication is served although nothing is advertised.
	mustIssueToken(t, "pki", s.post(integration_common.TokenEndpoint, tokenRequest(pkiClientId, nil),
		presented{certificates: []*x509.Certificate{s.leaf.cert}}))

	document := s.discovery()
	methods := listOf(document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported])
	if slices.Contains(methods, wicket.EndpointAuthenticationMethodsTlsClientAuth) ||
		slices.Contains(methods, wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth) {
		t.Fatalf("methods = %v advertise a tls method while MutualTls is off", methods)
	}
	if _, ok := document[wicket.DiscoveryMtlsEndpointAliases]; ok {
		t.Fatalf("aliases advertised while MutualTls is off")
	}
}

func TestIntrospectionAliasIsServedByTheIntrospectionHandler(t *testing.T) {
	s := enabledScene(t)
	token := s.post(integration_common.TokenEndpoint,
		tokenRequest(secretClientId, url.Values{"client_secret": {sharedSecret}}), presented{})
	mustIssueToken(t, "secret client", token)
	accessToken := token.field("access_token")

	introspect := func(path string) reply {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+path,
			strings.NewReader(url.Values{"token": {accessToken}}.Encode()))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth(apiName, sharedSecret)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return reply{status: response.StatusCode, body: string(body)}
	}

	alias := introspect("/" + wicket.ProtocolRoutePathsMtlsIntrospection)
	if alias.status != http.StatusOK || !strings.Contains(alias.body, `"active":true`) {
		t.Fatalf("introspection alias: status %d body %s, want an active token", alias.status, alias.body)
	}
	main := introspect(integration_common.IntrospectionEndpoint)
	if main.status != alias.status || main.body != alias.body {
		t.Fatalf("introspection alias answered %d %s, main endpoint %d %s", alias.status, alias.body, main.status, main.body)
	}
}

func listOf(value any) []string {
	values, _ := value.([]any)
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			out = append(out, text)
		}
	}
	return out
}
