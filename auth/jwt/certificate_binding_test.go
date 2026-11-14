// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/auth/jwt"
	"github.com/gonewx/wicket/claims"
)

func bindingCertificate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func thumbprintOf(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type fixedCertificates []*x509.Certificate

func (f fixedCertificates) ClientCertificates(*http.Request) []*x509.Certificate { return f }

// foreignToken is a SecurityToken that is not the default handler's.
type foreignToken struct{}

func (foreignToken) ValidTo() time.Time   { return time.Now().Add(time.Hour) }
func (foreignToken) ValidFrom() time.Time { return time.Now().Add(-time.Hour) }

type foreignValidator struct{}

func (foreignValidator) CanReadToken(string) bool { return true }

func (foreignValidator) ValidateToken(string, *jwt.TokenValidationParameters) (*claims.ClaimsPrincipal, jwt.SecurityToken, error) {
	identity := claims.NewClaimsIdentity(claims.WithAuthenticationType("foreign"))
	identity.AddClaim(claims.NewClaim(claims.WithClaimType(claims.NameIdentifier), claims.WithClaimValue(testSubject)))
	return claims.NewClaimsPrincipal(claims.WithClaimsPrincipalIdentity(identity)), foreignToken{}, nil
}

// failureRecorder answers 401 unless the request authenticated, and records
// the failure of the authentication result.
func failureRecorder(failure *error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := core.ResultFromContext(r.Context())
		if result != nil {
			*failure = result.Failure
		}
		protectedEndpoint()(w, r)
	}
}

func TestCertificateBindingCheck(t *testing.T) {
	t.Parallel()

	signingKey := newSigningKey(t, strings.Repeat("c", 128), testKid)
	verifyKeys := keySet(t, signingKey)
	bound := bindingCertificate(t, "bound")
	other := bindingCertificate(t, "other")

	boundToken := signToken(t, signingKey, func(tok jwxjwt.Token) {
		require.NoError(t, tok.Set("cnf", map[string]any{"x5t#S256": thumbprintOf(bound)}))
	})
	unboundToken := signToken(t, signingKey, nil)
	malformedToken := signToken(t, signingKey, func(tok jwxjwt.Token) {
		require.NoError(t, tok.Set("cnf", "not an object"))
	})

	tests := map[string]struct {
		source   jwt.CertificateSource
		token    string
		wantCode int
		wantFail bool
	}{
		"off: bound token without a certificate":  {nil, boundToken, http.StatusOK, false},
		"off: bound token with another one":       {nil, boundToken, http.StatusOK, false},
		"off: unbound token":                      {nil, unboundToken, http.StatusOK, false},
		"on: bound token with its certificate":    {fixedCertificates{bound}, boundToken, http.StatusOK, false},
		"on: bound token with another one":        {fixedCertificates{other}, boundToken, http.StatusUnauthorized, true},
		"on: bound token without a certificate":   {fixedCertificates(nil), boundToken, http.StatusUnauthorized, true},
		"on: unbound token without a certificate": {fixedCertificates(nil), unboundToken, http.StatusOK, false},
		"on: unbound token with a certificate":    {fixedCertificates{other}, unboundToken, http.StatusOK, false},
		"on: malformed confirmation":              {fixedCertificates{bound}, malformedToken, http.StatusUnauthorized, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := newTestOptions(t, verifyKeys, func(o *jwt.Options) { o.CertificateBindingSource = tc.source })
			var failure error
			response := serve(t, opts, "Bearer "+tc.token, failureRecorder(&failure))
			require.Equal(t, tc.wantCode, response.Code)
			if tc.wantFail {
				require.ErrorIs(t, failure, jwt.ErrCertificateBindingMismatch)
			} else {
				require.NoError(t, failure)
			}
		})
	}
}

func TestCertificateBindingRejectsAForeignSecurityToken(t *testing.T) {
	t.Parallel()

	signingKey := newSigningKey(t, strings.Repeat("d", 128), testKid)
	token := signToken(t, signingKey, nil)
	for name, tc := range map[string]struct {
		source   jwt.CertificateSource
		wantCode int
	}{
		"on":  {fixedCertificates{bindingCertificate(t, "any")}, http.StatusUnauthorized},
		"off": {nil, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			opts := newTestOptions(t, keySet(t, signingKey), func(o *jwt.Options) {
				o.SecurityTokenValidators = []jwt.SecurityTokenValidator{foreignValidator{}}
				o.CertificateBindingSource = tc.source
			})
			response := serve(t, opts, "Bearer "+token, protectedEndpoint())
			require.Equal(t, tc.wantCode, response.Code)
		})
	}
}
