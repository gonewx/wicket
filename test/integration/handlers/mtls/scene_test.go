// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	pkiClientId    = "pki-client"
	selfClientId   = "self-client"
	secretClientId = "secret-client"
	sharedSecret   = "secret"
	apiName        = "api1"
	scopeName      = "api"
	// certificateHeader carries the test client's certificate chain to the
	// injected certificate source: base64 DER values separated by commas,
	// leaf first. It exists only in these tests; wicket trusts no header.
	certificateHeader = "X-Test-Client-Certificates"
)

var serial atomic.Int64

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func issue(t *testing.T, template *x509.Certificate, parent *issued) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template.SerialNumber = big.NewInt(serial.Add(1))
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return issued{cert: cert, key: key}
}

func authority(t *testing.T, name string) issued {
	return issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil)
}

func clientCertificate(t *testing.T, commonName string, parent *issued) issued {
	return issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: commonName, Organization: []string{"Example"}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, parent)
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
	t          *testing.T
	pipeline   *integration_common.WicketPipeline
	root       issued
	leaf       issued
	selfSigned issued
}

type sceneOptions struct {
	enable    bool
	noRoots   bool
	mutualTls bool
}

func newScene(t *testing.T, o sceneOptions) *scene {
	t.Helper()
	s := &scene{t: t, pipeline: integration_common.NewWicketPipeline()}
	s.root = authority(t, "Test Root")
	s.leaf = clientCertificate(t, "pki-client", &s.root)
	s.selfSigned = clientCertificate(t, "self-client", nil)

	grants := []string{wicket.GrantTypeClientCredentials, wicket.GrantTypeDeviceCode}

	pki := storage_models.NewClient()
	pki.ClientId = pkiClientId
	pki.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsTlsClientAuth
	pki.TlsClientAuthSubjectDn = s.leaf.cert.Subject.String()
	// A secret is registered as well to show that it is not honoured.
	pkiSecret := storage_models.NewSecret()
	pkiSecret.Value = utils.Sha256(sharedSecret)
	pki.ClientSecrets = []*storage_models.Secret{pkiSecret}
	_ = pki.SetAllowedGrantTypes(grants)
	pki.AllowedScopes = []string{scopeName}

	self := storage_models.NewClient()
	self.ClientId = selfClientId
	self.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
	self.Jwks = `{"keys":[{"kty":"EC","x5c":["` + base64.StdEncoding.EncodeToString(s.selfSigned.cert.Raw) + `"]}]}`
	_ = self.SetAllowedGrantTypes(grants)
	self.AllowedScopes = []string{scopeName}

	shared := storage_models.NewClient()
	shared.ClientId = secretClientId
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(sharedSecret)
	shared.ClientSecrets = []*storage_models.Secret{secret}
	_ = shared.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
	shared.AllowedScopes = []string{scopeName}

	s.pipeline.Clients = []*storage_models.Client{pki, self, shared}

	api := storage_models.NewApiResource()
	api.Name = apiName
	api.Enabled = true
	apiSecret := storage_models.NewSecret()
	apiSecret.Value = utils.Sha256(sharedSecret)
	api.ApiSecrets = []*storage_models.Secret{apiSecret}
	api.Scopes = []string{scopeName}
	s.pipeline.ApiResources = append(s.pipeline.ApiResources, api)
	scope := storage_models.NewApiScope()
	scope.Name = scopeName
	s.pipeline.ApiScopes = append(s.pipeline.ApiScopes, scope)

	godi.GetRequired[*config_options.WicketOptions](s.pipeline.Root).MutualTls.Enabled = o.mutualTls
	cfg := s.pipeline.Root.ServerConfig()
	if o.enable {
		options := clientcert.Options{}
		if !o.noRoots {
			options.TrustedAuthorities = x509.NewCertPool()
			options.TrustedAuthorities.AddCert(s.root.cert)
		}
		cfg.EnableClientCertificateAuthentication(options)
		cfg.SetClientCertificateSource(headerSource{})
	}
	s.pipeline.Initialize()
	t.Cleanup(s.pipeline.TestServer.Close)
	return s
}

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

type presented struct {
	certificates []*x509.Certificate
	basic        bool
}

func (s *scene) post(endpoint string, values url.Values, p presented) reply {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		s.t.Fatalf("request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(p.certificates) > 0 {
		members := make([]string, 0, len(p.certificates))
		for _, certificate := range p.certificates {
			members = append(members, base64.StdEncoding.EncodeToString(certificate.Raw))
		}
		request.Header.Set(certificateHeader, strings.Join(members, ","))
	}
	if p.basic {
		request.SetBasicAuth(values.Get("client_id"), sharedSecret)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		s.t.Fatalf("post %s: %v", endpoint, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		s.t.Fatalf("read %s: %v", endpoint, err)
	}
	return reply{status: response.StatusCode, body: string(body)}
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

func tokenRequest(clientId string, extra url.Values) url.Values {
	values := url.Values{"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName}, "client_id": {clientId}}
	for name, value := range extra {
		values[name] = value
	}
	return values
}

func mustIssueToken(t *testing.T, name string, r reply) {
	t.Helper()
	if r.status != http.StatusOK || r.field("access_token") == "" {
		t.Fatalf("%s: status %d body %s, want a token", name, r.status, r.body)
	}
}

func mustBeInvalidClient(t *testing.T, name string, r reply) {
	t.Helper()
	if r.field("error") != "invalid_client" || r.field("access_token") != "" {
		t.Fatalf("%s: status %d body %s, want invalid_client", name, r.status, r.body)
	}
	if r.field("error_description") != "" || strings.Contains(r.body, "error_uri") {
		t.Fatalf("%s: failure carries a description: %s", name, r.body)
	}
}
