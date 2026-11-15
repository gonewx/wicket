// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauthorization

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/godi"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/storage"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

const (
	assertionClient   = "assertion.client"
	certificateClient = "certificate.client"
	// certificateHeader carries the test client's certificate to the
	// injected certificate source. It exists only in these tests.
	certificateHeader = "X-Test-Client-Certificate"
)

func encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// headerCertificateSource reads the test client certificate from a header,
// standing in for a TLS terminating proxy.
type headerCertificateSource struct{}

func (headerCertificateSource) ClientCertificates(request *http.Request) []*x509.Certificate {
	der, err := base64.StdEncoding.DecodeString(request.Header.Get(certificateHeader))
	if err != nil || len(der) == 0 {
		return nil
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return []*x509.Certificate{certificate}
}

type authenticationKeys struct {
	assertion   *ecdsa.PrivateKey
	certificate *x509.Certificate
}

func newAuthenticationKeys(t *testing.T) authenticationKeys {
	t.Helper()
	assertion, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: certificateClient},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &certificateKey.PublicKey, certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authenticationKeys{assertion: assertion, certificate: certificate}
}

func (k authenticationKeys) assertionKeySet(t *testing.T) string {
	t.Helper()
	point, err := k.assertion.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":%q,"y":%q}]}`, encode(point[1:33]), encode(point[33:]))
}

func (k authenticationKeys) sign(t *testing.T, audience string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "k1", "typ": "client-authentication+jwt"})
	payload, _ := json.Marshal(map[string]any{
		"iss": assertionClient,
		"sub": assertionClient,
		"aud": audience,
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": fmt.Sprintf("jti-%d", time.Now().UnixNano()),
	})
	input := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.assertion, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + encode(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func TestPushAcceptsEveryClientAuthentication(t *testing.T) {
	t.Parallel()
	keys := newAuthenticationKeys(t)
	s := newScene(t, sceneOptions{configure: func(p *integration_common.WicketPipeline) {
		assertion := newCodeClient(assertionClient)
		assertion.ClientSecrets = nil
		assertion.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
		assertion.Jwks = keys.assertionKeySet(t)

		certificate := newCodeClient(certificateClient)
		certificate.ClientSecrets = nil
		certificate.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
		certificate.Jwks = `{"keys":[{"kty":"EC","x5c":["` + base64.StdEncoding.EncodeToString(keys.certificate.Raw) + `"]}]}`

		p.Clients = append(p.Clients, assertion, certificate)

		godi.GetRequired[*config_options.WicketOptions](p.Root).MutualTls.Enabled = true
		cfg := p.Root.ServerConfig()
		cfg.SetReplayRegistry(replay.NewMemoryRegistry())
		cfg.EnablePrivateKeyJwt(clientassertion.Options{})
		cfg.EnableClientCertificateAuthentication(clientcert.Options{})
		cfg.SetClientCertificateSource(headerCertificateSource{})
	}})
	issuer, _ := discoveryDocument(t, s)["issuer"].(string)
	if issuer == "" {
		t.Fatal("no issuer")
	}

	protector := integration_common.NewPushedAuthorizationProtection().Create(storage.PushedAuthorizationRequestPurpose)
	pushes := map[string]func() reply{
		"client secret": func() reply {
			return s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, authorizationParameters(parClient), parClient, nil)
		},
		"private_key_jwt": func() reply {
			values := authorizationParameters(assertionClient)
			values.Set(wicket.AuthorizeRequestClientId, assertionClient)
			values.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
			values.Set("client_assertion", keys.sign(t, issuer))
			return s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, values, "", nil)
		},
		"mutual TLS on the alias": func() reply {
			values := authorizationParameters(certificateClient)
			values.Set(wicket.AuthorizeRequestClientId, certificateClient)
			header := http.Header{certificateHeader: {base64.StdEncoding.EncodeToString(keys.certificate.Raw)}}
			return s.postForm("/"+wicket.ProtocolRoutePathsMtlsPushedAuthorization, values, "", header)
		},
	}
	for name, push := range pushes {
		r := push()
		if r.status != http.StatusCreated {
			t.Fatalf("%s: status %d body %s", name, r.status, r.body)
		}
		requestURI := r.field("request_uri")
		record := s.record(requestURI)
		if record == nil {
			t.Fatalf("%s: no record", name)
		}
		if strings.Contains(string(record.Payload), "redirect_uri") {
			t.Fatalf("%s: payload carries plaintext", name)
		}
		stored, err := storage.UnprotectPushedAuthorizationParameters(protector, record.Payload)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, credential := range []string{"client_secret", "client_assertion", "client_assertion_type"} {
			if stored.Has(credential) {
				t.Fatalf("%s: stored parameters carry %s", name, credential)
			}
		}
	}

	// A request pushed with private_key_jwt completes at the authorize
	// endpoint.
	values := authorizationParameters(assertionClient)
	values.Set(wicket.AuthorizeRequestClientId, assertionClient)
	values.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	values.Set("client_assertion", keys.sign(t, issuer))
	r := s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, values, "", nil)
	if r.status != http.StatusCreated {
		t.Fatalf("push: status %d body %s", r.status, r.body)
	}
	s.login()
	o := s.authorize(s.authorizeUrl(assertionClient, r.field("request_uri")))
	if o.code == "" {
		t.Fatalf("no code: %+v", o)
	}
}
