// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

func TestAccessTokenHash(t *testing.T) {
	t.Parallel()
	// The fixed value was computed locally with
	// printf %s wicket-access-token | sha256sum, then base64url without padding.
	if got := AccessTokenHash("wicket-access-token"); got != "G3z8TIyzA35nGZzWelB1hMkBYUjYviTdnE3iRmVvS6Q" {
		t.Fatalf("AccessTokenHash = %q", got)
	}
	for _, token := range []string{"a", "eyJhbGciOiJFUzI1NiJ9.e30.c2ln", "8F3A-reference-handle"} {
		digest := sha256.Sum256([]byte(token))
		if want := base64.RawURLEncoding.EncodeToString(digest[:]); AccessTokenHash(token) != want {
			t.Fatalf("AccessTokenHash(%q) = %q, want %q", token, AccessTokenHash(token), want)
		}
	}
}

func TestVerifyForResourceJudgesTheAccessTokenHash(t *testing.T) {
	t.Parallel()
	const token = "access-token-1"
	key := newEcKey(t, elliptic.P256())
	verifier := NewVerifier(Options{})
	cases := map[string]struct {
		ath     any
		present bool
		token   string
		wantOk  bool
	}{
		"matching hash":         {ath: AccessTokenHash(token), present: true, token: token, wantOk: true},
		"hash of another token": {ath: AccessTokenHash("access-token-2"), present: true, token: token},
		"missing":               {token: token},
		"not a string":          {ath: 12, present: true, token: token},
		"null":                  {ath: nil, present: true, token: token},
		"empty":                 {ath: "", present: true, token: token},
		"padded encoding":       {ath: AccessTokenHash(token) + "=", present: true, token: token},
		"empty access token":    {ath: AccessTokenHash(""), present: true, token: ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims()
			if tc.present {
				claims["ath"] = tc.ath
			}
			proof := key.sign(t, "ES256", validHeader(key, "ES256"), claims)
			accepted, err := verifier.VerifyForResource([]string{proof}, "POST", testEndpoint, tc.token, testNow)
			if tc.wantOk {
				if err != nil {
					t.Fatalf("VerifyForResource: %v", err)
				}
				if accepted.Thumbprint == "" || accepted.JwtId != "proof-1" {
					t.Fatalf("proof = %+v", accepted)
				}
				return
			}
			if !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("err = %v, want ErrInvalidProof", err)
			}
		})
	}
}

func TestVerifyForResourceRunsTheProofChecks(t *testing.T) {
	t.Parallel()
	const token = "access-token-1"
	key := newEcKey(t, elliptic.P256())
	claims := validClaims()
	claims["ath"] = AccessTokenHash(token)
	proof := key.sign(t, "ES256", validHeader(key, "ES256"), claims)
	verifier := NewVerifier(Options{})

	if _, err := verifier.VerifyForResource([]string{proof}, "GET", testEndpoint, token, testNow); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("htm: err = %v", err)
	}
	if _, err := verifier.VerifyForResource([]string{proof}, "POST", "https://as.example/connect/userinfo", token, testNow); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("htu: err = %v", err)
	}
	if _, err := verifier.VerifyForResource(nil, "POST", testEndpoint, token, testNow); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("no proof: err = %v", err)
	}
	if _, err := verifier.VerifyForResource([]string{proof, proof}, "POST", testEndpoint, token, testNow); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("two proofs: err = %v", err)
	}
}

func TestConfirmationThumbprint(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		cnf        any
		thumbprint string
		bound      bool
		malformed  bool
	}{
		"absent":                  {cnf: nil},
		"object without jkt":      {cnf: map[string]any{"x5t#S256": "abc"}},
		"object with jkt":         {cnf: map[string]any{"jkt": "abc"}, thumbprint: "abc", bound: true},
		"object with both":        {cnf: map[string]any{"jkt": "abc", "x5t#S256": "def"}, thumbprint: "abc", bound: true},
		"JSON text with jkt":      {cnf: `{"jkt":"abc"}`, thumbprint: "abc", bound: true},
		"JSON text without jkt":   {cnf: `{"x5t#S256":"def"}`},
		"broken JSON text":        {cnf: `{"jkt":`, malformed: true},
		"JSON text not an object": {cnf: `["jkt"]`, malformed: true},
		"JSON null text":          {cnf: `null`, malformed: true},
		"empty text":              {cnf: ``, malformed: true},
		"numeric jkt":             {cnf: map[string]any{"jkt": 12.0}, malformed: true},
		"empty jkt":               {cnf: map[string]any{"jkt": ""}, malformed: true},
		"null jkt":                {cnf: map[string]any{"jkt": nil}, malformed: true},
		"numeric jkt in text":     {cnf: `{"jkt":12}`, malformed: true},
		"other type":              {cnf: 12, malformed: true},
		"string map":              {cnf: map[string]string{"jkt": "abc"}, malformed: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			thumbprint, bound, err := ConfirmationThumbprint(tc.cnf)
			if tc.malformed {
				if !errors.Is(err, ErrMalformedConfirmation) || bound || thumbprint != "" {
					t.Fatalf("= %q %v %v, want ErrMalformedConfirmation", thumbprint, bound, err)
				}
				return
			}
			if err != nil || bound != tc.bound || thumbprint != tc.thumbprint {
				t.Fatalf("= %q %v %v, want %q %v", thumbprint, bound, err, tc.thumbprint, tc.bound)
			}
		})
	}
}

func TestThumbprintMatches(t *testing.T) {
	t.Parallel()
	proof := Proof{Thumbprint: "abc"}
	if !ThumbprintMatches(proof, "abc") {
		t.Fatal("same thumbprint does not match")
	}
	for _, other := range []string{"abd", "ab", "abcd", ""} {
		if ThumbprintMatches(proof, other) {
			t.Fatalf("thumbprint %q matches", other)
		}
	}
	if ThumbprintMatches(Proof{}, "") {
		t.Fatal("empty thumbprints match")
	}
}
