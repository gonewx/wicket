// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	pkiClientId    = "pki-client"
	selfClientId   = "self-client"
	secretClientId = "secret-client"
)

type fixture struct {
	root, intermediate issued
	leaf               issued
	selfSigned         issued
	clients            mapClients
	inner              *innerValidator
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	f.root = authority(t, "Test Root", nil)
	f.intermediate = authority(t, "Test Intermediate", &f.root)
	f.leaf = issue(t, leafTemplate(), &f.intermediate)
	f.selfSigned = issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "self"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, nil)

	pki := storage_models.NewClient()
	pki.ClientId = pkiClientId
	pki.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsTlsClientAuth
	pki.TlsClientAuthSubjectDn = f.leaf.cert.Subject.String()

	self := storage_models.NewClient()
	self.ClientId = selfClientId
	self.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
	self.Jwks = jwksWith(issue(t, leafTemplate(), nil).cert, f.selfSigned.cert)

	secret := storage_models.NewClient()
	secret.ClientId = secretClientId

	f.clients = mapClients{pkiClientId: pki, selfClientId: self, secretClientId: secret}
	f.inner = &innerValidator{clients: f.clients}
	return f
}

func (f *fixture) authenticator(source CertificateSource, enabled ...string) *ClientAuthenticator {
	return NewClientAuthenticator(
		f.inner,
		f.clients,
		source,
		Options{TrustedAuthorities: poolOf(f.root.cert)},
		func(method string) bool {
			for _, candidate := range enabled {
				if candidate == method {
					return true
				}
			}
			return false
		},
		fixedClock{now: testNow},
		nil,
	)
}

var bothMethods = []string{
	wicket.EndpointAuthenticationMethodsTlsClientAuth,
	wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
}

func mustSucceed(t *testing.T, result *validators_models.ClientSecretValidationResult, clientId string) {
	t.Helper()
	if result == nil || result.Error != nil || result.Client == nil || result.Client.ClientId != clientId {
		t.Fatalf("result = %+v, want success for %s", result, clientId)
	}
	want := &struct{ Id, Type string }{clientId, wicket.ParsedSecretTypesX509Certificate}
	if result.Secret == nil || result.Secret.Id != want.Id || result.Secret.Type != want.Type || result.Secret.Credential != "" {
		t.Fatalf("secret = %+v, want an X509Certificate secret without credential", result.Secret)
	}
}

func mustFail(t *testing.T, name string, result *validators_models.ClientSecretValidationResult) {
	t.Helper()
	want := &validators_models.ClientSecretValidationResult{}
	*want = *validators_models.NewClientSecretValidationResult()
	want.Error = wicket.TokenErrorsInvalidClient
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("%s: result = %+v, want bare invalid_client", name, result)
	}
}

func TestPkiCertificateAuthenticates(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(nil, bothMethods...)
	values := url.Values{"client_id": {pkiClientId}}
	mustSucceed(t, a.Validate(tlsRequest(values, f.leaf.cert, f.intermediate.cert)), pkiClientId)
	if f.inner.calls.Load() != 0 {
		t.Fatalf("inner validator consulted for a mutual TLS client")
	}
}

func TestPkiSubjectAttributeMatching(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(nil, bothMethods...)
	cases := []struct {
		name  string
		set   func(*storage_models.Client)
		match bool
	}{
		{"subject dn", func(c *storage_models.Client) { c.TlsClientAuthSubjectDn = f.leaf.cert.Subject.String() }, true},
		{"subject dn differs", func(c *storage_models.Client) { c.TlsClientAuthSubjectDn = "CN=client-two,O=Example,C=US" }, false},
		{"subject dn in another order", func(c *storage_models.Client) { c.TlsClientAuthSubjectDn = "C=US,O=Example,CN=client-one" }, false},
		{"san dns ignores case", func(c *storage_models.Client) { c.TlsClientAuthSanDns = "client.example.test" }, true},
		{"san dns differs", func(c *storage_models.Client) { c.TlsClientAuthSanDns = "other.example.test" }, false},
		{"san dns no wildcard expansion", func(c *storage_models.Client) { c.TlsClientAuthSanDns = "*.example.test" }, false},
		{"san uri", func(c *storage_models.Client) { c.TlsClientAuthSanUri = "https://client.example.test/app" }, true},
		{"san uri differs", func(c *storage_models.Client) { c.TlsClientAuthSanUri = "https://client.example.test/other" }, false},
		{"san ip v4", func(c *storage_models.Client) { c.TlsClientAuthSanIp = "192.0.2.10" }, true},
		{"san ip v6 other spelling", func(c *storage_models.Client) { c.TlsClientAuthSanIp = "2001:0db8:0:0:0:0:0:1" }, true},
		{"san ip differs", func(c *storage_models.Client) { c.TlsClientAuthSanIp = "192.0.2.11" }, false},
		{"san ip unparsable", func(c *storage_models.Client) { c.TlsClientAuthSanIp = "not-an-ip" }, false},
		{"san email", func(c *storage_models.Client) { c.TlsClientAuthSanEmail = "client@example.test" }, true},
		{"san email differs", func(c *storage_models.Client) { c.TlsClientAuthSanEmail = "other@example.test" }, false},
		{"no attribute", func(*storage_models.Client) {}, false},
		{"two attributes", func(c *storage_models.Client) {
			c.TlsClientAuthSubjectDn = f.leaf.cert.Subject.String()
			c.TlsClientAuthSanEmail = "client@example.test"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := storage_models.NewClient()
			client.ClientId = pkiClientId
			client.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsTlsClientAuth
			tc.set(client)
			f.clients[pkiClientId] = client
			result := a.Validate(tlsRequest(url.Values{"client_id": {pkiClientId}}, f.leaf.cert, f.intermediate.cert))
			if tc.match {
				mustSucceed(t, result, pkiClientId)
			} else {
				mustFail(t, tc.name, result)
			}
		})
	}
}

func TestPkiChainRules(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(nil, bothMethods...)
	values := url.Values{"client_id": {pkiClientId}}

	foreignRoot := authority(t, "Foreign Root", nil)
	foreignIntermediate := authority(t, "Test Intermediate", &foreignRoot)
	foreignLeaf := issue(t, leafTemplate(), &foreignIntermediate)

	serverOnly := leafTemplate()
	serverOnly.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	serverLeaf := issue(t, serverOnly, &f.intermediate)

	noUsage := leafTemplate()
	noUsage.ExtKeyUsage = nil
	noUsageLeaf := issue(t, noUsage, &f.intermediate)

	expired := leafTemplate()
	expired.NotBefore = testNow.Add(-2 * time.Hour)
	expired.NotAfter = testNow.Add(-time.Hour)
	expiredLeaf := issue(t, expired, &f.intermediate)

	mustFail(t, "untrusted chain", a.Validate(tlsRequest(values, foreignLeaf.cert, foreignIntermediate.cert)))
	mustFail(t, "missing intermediate", a.Validate(tlsRequest(values, f.leaf.cert)))
	mustFail(t, "server auth only", a.Validate(tlsRequest(values, serverLeaf.cert, f.intermediate.cert)))
	mustFail(t, "expired at the injected time", a.Validate(tlsRequest(values, expiredLeaf.cert, f.intermediate.cert)))
	mustFail(t, "self-signed for pki", a.Validate(tlsRequest(values, f.selfSigned.cert)))
	// Go accepts a certificate without an extended key usage.
	mustSucceed(t, a.Validate(tlsRequest(values, noUsageLeaf.cert, f.intermediate.cert)), pkiClientId)

	withoutRoots := NewClientAuthenticator(f.inner, f.clients, nil, Options{}, func(string) bool { return true }, fixedClock{now: testNow}, nil)
	mustFail(t, "no trusted authorities", withoutRoots.Validate(tlsRequest(values, f.leaf.cert, f.intermediate.cert)))
}

func TestSelfSignedCertificateMatching(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(nil, bothMethods...)
	values := url.Values{"client_id": {selfClientId}}

	mustSucceed(t, a.Validate(tlsRequest(values, f.selfSigned.cert)), selfClientId)

	// Validity is not checked: the registration itself establishes trust.
	stale := issue(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "stale"},
		NotBefore: testNow.Add(-48 * time.Hour),
		NotAfter:  testNow.Add(-24 * time.Hour),
	}, nil)
	f.clients[selfClientId].Jwks = jwksWith(stale.cert)
	mustSucceed(t, a.Validate(tlsRequest(values, stale.cert)), selfClientId)

	other := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "self"}}, nil)
	mustFail(t, "not registered", a.Validate(tlsRequest(values, other.cert)))

	f.clients[selfClientId].Jwks = `{"keys":[{"kty":"EC","x5c":["` + "%%%" + `"]},{"kty":"EC"}]}`
	mustFail(t, "undecodable x5c", a.Validate(tlsRequest(values, f.selfSigned.cert)))
	f.clients[selfClientId].Jwks = `not json`
	mustFail(t, "unparsable jwks", a.Validate(tlsRequest(values, f.selfSigned.cert)))
	f.clients[selfClientId].Jwks = ""
	mustFail(t, "no jwks", a.Validate(tlsRequest(values, f.selfSigned.cert)))
}

func TestOnlyTheFirstX5cMemberIsRegistered(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(nil, bothMethods...)
	f.clients[selfClientId].Jwks = `{"keys":[{"kty":"EC","x5c":["` +
		jwksMember(f.leaf.cert) + `","` + jwksMember(f.selfSigned.cert) + `"]}]}`
	mustFail(t, "second x5c member", a.Validate(tlsRequest(url.Values{"client_id": {selfClientId}}, f.selfSigned.cert)))
}

func jwksMember(cert *x509.Certificate) string {
	set := jwksWith(cert)
	const prefix = `{"keys":[{"kty":"EC","x5c":["`
	return set[len(prefix) : len(set)-len(`"]}]}`)]
}

func TestFailuresAreIndistinguishable(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(nil, bothMethods...)
	pki := url.Values{"client_id": {pkiClientId}}
	self := url.Values{"client_id": {selfClientId}}
	with := func(base url.Values, name, value string) url.Values {
		values := url.Values{}
		for k, v := range base {
			values[k] = v
		}
		values.Set(name, value)
		return values
	}

	basic := tlsRequest(pki, f.leaf.cert, f.intermediate.cert)
	basic.SetBasicAuth(pkiClientId, "secret")

	cases := map[string]*validators_models.ClientSecretValidationResult{
		"no certificate pki":         a.Validate(tlsRequest(pki)),
		"no tls":                     a.Validate(formRequest(self)),
		"client_secret alongside":    a.Validate(tlsRequest(with(pki, "client_secret", "secret"), f.leaf.cert, f.intermediate.cert)),
		"client_assertion alongside": a.Validate(tlsRequest(with(self, "client_assertion", "x.y.z"), f.selfSigned.cert)),
		"assertion type alongside":   a.Validate(tlsRequest(with(self, "client_assertion_type", "urn:x"), f.selfSigned.cert)),
		"basic alongside":            a.Validate(basic),
	}
	for name, result := range cases {
		mustFail(t, name, result)
	}

	onlySelf := f.authenticator(nil, wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth)
	mustFail(t, "method not enabled", onlySelf.Validate(tlsRequest(pki, f.leaf.cert, f.intermediate.cert)))
}

func TestOtherClientsGoToTheInnerValidator(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(nil, bothMethods...)

	withCert := a.Validate(tlsRequest(url.Values{"client_id": {secretClientId}, "client_secret": {"secret"}}, f.leaf.cert, f.intermediate.cert))
	if withCert.Error != nil || withCert.Client.ClientId != secretClientId {
		t.Fatalf("secret client with a certificate: %+v", withCert)
	}
	wrong := a.Validate(formRequest(url.Values{"client_id": {secretClientId}, "client_secret": {"wrong"}}))
	if wrong.Error != errInner {
		t.Fatalf("inner failure not passed through: %+v", wrong)
	}
	unknown := a.Validate(formRequest(url.Values{"client_id": {"unknown"}}))
	if unknown.Error != errInner {
		t.Fatalf("unknown client not handed to the inner validator: %+v", unknown)
	}
	if f.inner.calls.Load() != 3 {
		t.Fatalf("inner validator calls = %d, want 3", f.inner.calls.Load())
	}
}

func TestMutualTlsClientCannotAuthenticateWithoutClientId(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(nil, bothMethods...)
	// Basic credentials carry the client id outside the form; the inner
	// validator accepts them, but the client is registered for mutual TLS.
	request := tlsRequest(url.Values{}, f.leaf.cert, f.intermediate.cert)
	request.SetBasicAuth(pkiClientId, "secret")
	mustFail(t, "basic without client_id", a.Validate(request))

	// A JSON body is not read for client_id.
	jsonRequest := tlsRequest(url.Values{"client_id": {pkiClientId}}, f.leaf.cert, f.intermediate.cert)
	jsonRequest.Header.Set("Content-Type", "application/json")
	if result := a.Validate(jsonRequest); result.Error == nil {
		t.Fatalf("non-form request authenticated: %+v", result)
	}
}

func TestInjectedSourceReplacesTheConnection(t *testing.T) {
	f := newFixture(t)
	a := f.authenticator(staticSource{f.selfSigned.cert}, bothMethods...)
	mustSucceed(t, a.Validate(formRequest(url.Values{"client_id": {selfClientId}})), selfClientId)
	// The connection certificate is ignored once a source is injected.
	empty := f.authenticator(staticSource(nil), bothMethods...)
	mustFail(t, "empty injected source", empty.Validate(tlsRequest(url.Values{"client_id": {selfClientId}}, f.selfSigned.cert)))
}

func TestConnectionCertificateSource(t *testing.T) {
	f := newFixture(t)
	source := ConnectionCertificateSource{}
	if got := source.ClientCertificates(formRequest(nil)); got != nil {
		t.Fatalf("request without TLS: %v", got)
	}
	if got := source.ClientCertificates(tlsRequest(nil)); got != nil {
		t.Fatalf("TLS without peer certificates: %v", got)
	}
	if got := source.ClientCertificates(nil); got != nil {
		t.Fatalf("nil request: %v", got)
	}
	got := source.ClientCertificates(tlsRequest(nil, f.leaf.cert, f.intermediate.cert))
	if len(got) != 2 || got[0] != f.leaf.cert || got[1] != f.intermediate.cert {
		t.Fatalf("peer certificates = %v, want leaf then intermediate", got)
	}
}

func TestMethodParsers(t *testing.T) {
	for _, parser := range []MethodParser{NewTlsClientAuthParser(), NewSelfSignedTlsClientAuthParser()} {
		secret, err := parser.Parse(tlsRequest(url.Values{"client_id": {pkiClientId}}))
		if secret != nil || err != nil {
			t.Fatalf("%s Parse = %v, %v; want nil, nil", parser.AuthenticationMethod(), secret, err)
		}
	}
	if NewTlsClientAuthParser().AuthenticationMethod() != wicket.EndpointAuthenticationMethodsTlsClientAuth ||
		NewSelfSignedTlsClientAuthParser().AuthenticationMethod() != wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth {
		t.Fatalf("method names do not follow RFC 8705")
	}
	if !IsCertificateMethod("tls_client_auth") || !IsCertificateMethod("self_signed_tls_client_auth") || IsCertificateMethod("private_key_jwt") || IsCertificateMethod("") {
		t.Fatalf("IsCertificateMethod misclassifies")
	}
}
