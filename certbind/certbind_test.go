// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package certbind

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestThumbprintIsTheUnpaddedBase64UrlSha256OfTheDer(t *testing.T) {
	cert := selfSigned(t, "a")
	digest := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if got := Thumbprint(cert); got != want {
		t.Fatalf("Thumbprint = %q, want %q", got, want)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(Confirmation(cert)), &decoded); err != nil {
		t.Fatalf("Confirmation is not JSON: %v", err)
	}
	if len(decoded) != 1 || decoded[ThumbprintMember] != want {
		t.Fatalf("Confirmation = %v, want only %s = %q", decoded, ThumbprintMember, want)
	}
}

func TestCheck(t *testing.T) {
	bound := selfSigned(t, "bound")
	other := selfSigned(t, "other")
	thumb := Thumbprint(bound)
	cases := []struct {
		name         string
		cnf          any
		certificates []*x509.Certificate
		want         error
	}{
		{"nil cnf without certificate", nil, nil, nil},
		{"nil cnf with certificate", nil, []*x509.Certificate{other}, nil},
		{"object without thumbprint", map[string]any{"jkt": "x"}, nil, nil},
		{"text without thumbprint", `{"jkt":"x"}`, nil, nil},
		{"matching object", map[string]any{ThumbprintMember: thumb}, []*x509.Certificate{bound}, nil},
		{"matching text", Confirmation(bound), []*x509.Certificate{bound, other}, nil},
		{"mismatch", map[string]any{ThumbprintMember: thumb}, []*x509.Certificate{other}, ErrCertificateMismatch},
		{"only an intermediate matches", map[string]any{ThumbprintMember: thumb}, []*x509.Certificate{other, bound}, ErrCertificateMismatch},
		{"no certificates", map[string]any{ThumbprintMember: thumb}, nil, ErrCertificateMissing},
		{"nil leaf", map[string]any{ThumbprintMember: thumb}, []*x509.Certificate{nil, bound}, ErrCertificateMissing},
		{"empty thumbprint", map[string]any{ThumbprintMember: ""}, []*x509.Certificate{bound}, ErrMalformedConfirmation},
		{"numeric thumbprint", map[string]any{ThumbprintMember: 1.0}, []*x509.Certificate{bound}, ErrMalformedConfirmation},
		{"null thumbprint", map[string]any{ThumbprintMember: nil}, []*x509.Certificate{bound}, ErrMalformedConfirmation},
		{"array cnf", []any{map[string]any{ThumbprintMember: thumb}}, []*x509.Certificate{bound}, ErrMalformedConfirmation},
		{"number cnf", 3.0, []*x509.Certificate{bound}, ErrMalformedConfirmation},
		{"unparsable text", `{"x5t#S256":`, []*x509.Certificate{bound}, ErrMalformedConfirmation},
		{"text of an array", `["x"]`, []*x509.Certificate{bound}, ErrMalformedConfirmation},
		{"text of null", `null`, []*x509.Certificate{bound}, ErrMalformedConfirmation},
		{"empty text", ``, []*x509.Certificate{bound}, ErrMalformedConfirmation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.cnf, tc.certificates); !errors.Is(got, tc.want) || (tc.want == nil && got != nil) {
				t.Fatalf("Check = %v, want %v", got, tc.want)
			}
		})
	}
}
