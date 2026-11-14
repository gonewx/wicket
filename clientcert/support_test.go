// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

var serial atomic.Int64

// issued is a certificate with its private key.
type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// issue signs template with parent; a nil parent makes it self-signed.
func issue(t *testing.T, template *x509.Certificate, parent *issued) issued {
	t.Helper()
	key := newKey(t)
	template.SerialNumber = big.NewInt(serial.Add(1))
	if template.NotBefore.IsZero() {
		template.NotBefore = testNow.Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = testNow.Add(time.Hour)
	}
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

func authority(t *testing.T, name string, parent *issued) issued {
	return issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, parent)
}

// leafTemplate is a client certificate carrying every matchable attribute.
func leafTemplate() *x509.Certificate {
	uri, _ := url.Parse("https://client.example.test/app")
	return &x509.Certificate{
		Subject:        pkix.Name{CommonName: "client-one", Organization: []string{"Example"}, Country: []string{"US"}},
		DNSNames:       []string{"Client.Example.Test"},
		URIs:           []*url.URL{uri},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")},
		EmailAddresses: []string{"client@example.test"},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func jwksWith(certs ...*x509.Certificate) string {
	keys := make([]string, 0, len(certs))
	for _, cert := range certs {
		keys = append(keys, `{"kty":"EC","x5c":["`+base64.StdEncoding.EncodeToString(cert.Raw)+`"]}`)
	}
	return `{"keys":[` + strings.Join(keys, ",") + `]}`
}

type mapClients map[string]*storage_models.Client

func (m mapClients) FindClientById(_ context.Context, id string) (*storage_models.Client, error) {
	if client, ok := m[id]; ok {
		return client, nil
	}
	return nil, storage.ErrNotFound
}

// innerValidator stands for every other authentication method; it accepts
// any request whose client_secret is "secret" and counts its calls.
type innerValidator struct {
	clients mapClients
	calls   atomic.Int64
}

func (v *innerValidator) Validate(request *http.Request) *validators_models.ClientSecretValidationResult {
	v.calls.Add(1)
	result := validators_models.NewClientSecretValidationResult()
	id, secret, basic := request.BasicAuth()
	if !basic {
		id, secret = request.PostFormValue("client_id"), request.PostFormValue("client_secret")
	}
	client, ok := v.clients[id]
	if !ok || secret != "secret" {
		result.Error = errInner
		return result
	}
	result.Client = client
	return result
}

type innerError struct{}

func (innerError) Error() string { return "inner failure" }

var errInner = innerError{}

// staticSource yields fixed certificates.
type staticSource []*x509.Certificate

func (s staticSource) ClientCertificates(*http.Request) []*x509.Certificate { return s }

func formRequest(values url.Values) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func tlsRequest(values url.Values, certs ...*x509.Certificate) *http.Request {
	request := formRequest(values)
	request.TLS = &tls.ConnectionState{PeerCertificates: certs}
	return request
}
