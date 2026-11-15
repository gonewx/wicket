// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func userInfoCertificate(t *testing.T, name string) *x509.Certificate {
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

func userInfoThumbprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type presentedCertificates []*x509.Certificate

func (p presentedCertificates) ClientCertificates(*http.Request) []*x509.Certificate { return p }

func userInfoResultWith(cnf ...any) *validators_models.UserInfoRequestValidationResult {
	result := validators_models.NewUserInfoRequestValidationResult()
	result.Subject = claims.NewClaimsPrincipal()
	result.TokenValidationResult = validators_models.NewTokenValidationResult()
	result.TokenValidationResult.Claims = []*claims.Claim{
		claims.NewClaim(claims.WithClaimType(wicket.JwtClaimTypesSubject), claims.WithClaimValue("subject-1")),
	}
	for _, value := range cnf {
		result.TokenValidationResult.Claims = append(result.TokenValidationResult.Claims,
			claims.NewClaim(claims.WithClaimType(wicket.JwtClaimTypesConfirmation), claims.WithClaimValue(value)))
	}
	return result
}

func TestUserInfoChecksTheCertificateBinding(t *testing.T) {
	t.Parallel()

	bound := userInfoCertificate(t, "bound")
	other := userInfoCertificate(t, "other")
	confirmation := map[string]any{"x5t#S256": userInfoThumbprint(bound)}

	cases := []struct {
		name   string
		result *validators_models.UserInfoRequestValidationResult
		// source nil leaves the handler on its default, the TLS connection.
		source  ClientCertificateSource
		peer    []*x509.Certificate
		wantOk  bool
		noSetup bool
	}{
		{name: "bound token with its certificate", result: userInfoResultWith(confirmation), source: presentedCertificates{bound}, wantOk: true},
		{name: "bound token as JSON text", result: userInfoResultWith(`{"x5t#S256":"` + userInfoThumbprint(bound) + `"}`), source: presentedCertificates{bound}, wantOk: true},
		{name: "bound token over the TLS connection", result: userInfoResultWith(confirmation), peer: []*x509.Certificate{bound}, wantOk: true},
		{name: "bound token over the TLS connection without setter", result: userInfoResultWith(confirmation), peer: []*x509.Certificate{bound}, wantOk: true, noSetup: true},
		{name: "bound token with another certificate", result: userInfoResultWith(confirmation), source: presentedCertificates{other}},
		{name: "bound token without a certificate", result: userInfoResultWith(confirmation), source: presentedCertificates(nil)},
		{name: "bound token without TLS", result: userInfoResultWith(confirmation)},
		{name: "unbound token without a certificate", result: userInfoResultWith(), source: presentedCertificates(nil), wantOk: true},
		{name: "confirmation without a thumbprint", result: userInfoResultWith(map[string]any{"other": "x"}), wantOk: true},
		// A DPoP bound token never passes as a bearer token (RFC 9449 section 7.2).
		{name: "DPoP bound token as a bearer token", result: userInfoResultWith(map[string]any{"jkt": "x"})},
		{name: "confirmation that is not an object", result: userInfoResultWith("text"), source: presentedCertificates{bound}},
		{name: "null confirmation", result: userInfoResultWith(nil), source: presentedCertificates{bound}},
		{name: "empty thumbprint", result: userInfoResultWith(map[string]any{"x5t#S256": ""}), source: presentedCertificates{bound}},
		{name: "two confirmations", result: userInfoResultWith(confirmation, confirmation), source: presentedCertificates{bound}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			handler := newUserInfoHandlerUnderTest(tc.result, map[string]any{"sub": "subject-1"})
			if !tc.noSetup {
				handler.SetClientCertificateSource(tc.source)
			}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/userinfo", nil)
			request.Header.Set("Authorization", "Bearer good-token")
			if tc.peer != nil {
				request.TLS = &tls.ConnectionState{PeerCertificates: tc.peer}
			}
			if err := handler.Process(recorder, request); err != nil {
				t.Fatalf("Process: %v", err)
			}
			if tc.wantOk {
				if recorder.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200", recorder.Code)
				}
				if strings.Contains(recorder.Body.String(), "cnf") {
					t.Fatalf("body = %s carries cnf", recorder.Body.String())
				}
				return
			}
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", recorder.Code)
			}
			challenge := strings.Join(recorder.Header()["www-authenticate"], " ")
			if !strings.Contains(challenge, `error="invalid_token"`) {
				t.Fatalf("challenge = %q, want invalid_token", challenge)
			}
			if strings.Contains(challenge, "error_description") {
				t.Fatalf("challenge = %q discloses a reason", challenge)
			}
		})
	}
}
