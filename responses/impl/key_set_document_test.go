// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"testing"

	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/tokens"
)

type staticValidationKeys struct {
	keys []*core_models.SecurityKeyInfo
}

func (s staticValidationKeys) GetSigningCredentials([]string) (*tokens.SigningCredentials, error) {
	return nil, nil
}
func (s staticValidationKeys) GetAllSigningCredentials() ([]*tokens.SigningCredentials, error) {
	return nil, nil
}
func (s staticValidationKeys) GetValidationKeys() ([]*core_models.SecurityKeyInfo, error) {
	return s.keys, nil
}

func TestCreateJwkDocumentPublishesStableKidWithoutPrivateMaterial(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec: %v", err)
	}

	for name, tc := range map[string]struct {
		key         any
		algorithm   string
		kid         string
		privateJWKD string
	}{
		"rsa public key": {
			key:         &rsaKey.PublicKey,
			algorithm:   "RS256",
			kid:         "rsa-kid",
			privateJWKD: "d",
		},
		"ec public key": {
			key:         &ecKey.PublicKey,
			algorithm:   "ES256",
			kid:         "ec-kid",
			privateJWKD: "d",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			g := &DiscoveryResponseGenerator{
				keys: staticValidationKeys{keys: []*core_models.SecurityKeyInfo{
					{Key: tc.key, SigningAlgorithm: tc.algorithm, KeyId: tc.kid},
				}},
				logger: slog.Default(),
			}

			docs, err := g.CreateJwkDocument()
			if err != nil {
				t.Fatalf("CreateJwkDocument: %v", err)
			}
			if len(docs) != 1 {
				t.Fatalf("jwk count = %d, want 1", len(docs))
			}

			raw, err := json.Marshal(docs[0])
			if err != nil {
				t.Fatalf("marshal jwk: %v", err)
			}
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("unmarshal jwk: %v", err)
			}

			if fields["kid"] != tc.kid {
				t.Fatalf("kid = %v, want %q (stable passthrough)", fields["kid"], tc.kid)
			}
			if fields["alg"] != tc.algorithm {
				t.Fatalf("alg = %v, want %q", fields["alg"], tc.algorithm)
			}
			if _, leaked := fields[tc.privateJWKD]; leaked {
				t.Fatal("JWKS leaked private material")
			}
		})
	}
}
