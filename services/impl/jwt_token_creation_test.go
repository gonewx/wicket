// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/keymgmt"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
)

func rs256Manager() *keymgmt.Manager {
	return keymgmt.NewManager(keymgmt.Config{
		Enabled:            true,
		AutoCreate:         true,
		RotationInterval:   time.Hour,
		ActivationLeadTime: 10 * time.Minute,
		RetentionDuration:  20 * time.Minute,
		AllowedAlgorithms:  []string{keymgmt.AlgRS256},
		DefaultAlgorithm:   keymgmt.AlgRS256,
		CacheTTL:           time.Minute,
		ClockSkew:          time.Minute,
	}, keymgmt.NewMemoryRecordStore(), reversibleProvider{}, fixedClock{}, rand.Reader, nil)
}

// TestCreateTokenHeaderKidResolvesThroughValidationKeys closes the end-to-end
// kid↔validation-key consistency gap left open by the key-management story: a
// token signed through the auto key manager must advertise a header kid that is
// present in the published validation key set, and that key set must actually
// verify the signature. This is the manager-level proof that the signing key id
// and the validation-side re-derived key id agree.
func TestCreateTokenHeaderKidResolvesThroughValidationKeys(t *testing.T) {
	manager := rs256Manager()
	keys := NewKeyMaterialService(nil, nil, manager, nil)
	creator := NewTokenCreationService(keys, test_common.NewStubClock(), config_options.NewWicketOptions(), nil)

	token := &storage_models.Token{
		Type:      wicket.TokenTypesAccessToken,
		Issuer:    "https://issuer.wicket.test",
		Audiences: []string{"resource"},
		Lifetime:  600,
		Claims: []*claimspkg.Claim{
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue("alice")),
		},
	}

	signed, err := creator.CreateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	// The signed token advertises a non-empty kid header.
	msg, err := jws.Parse([]byte(signed))
	if err != nil {
		t.Fatalf("parse jws: %v", err)
	}
	headerKid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
	if !ok || headerKid == "" {
		t.Fatal("signed token carries no kid header")
	}

	// That kid is present in the published validation key set, and building the
	// key set the way the validation side does (re-deriving the RFC 7638 key id)
	// yields a set that verifies the signature.
	validationKeys, err := keys.GetValidationKeys(context.Background())
	if err != nil {
		t.Fatalf("validation keys: %v", err)
	}
	set := jwk.NewSet()
	found := false
	for _, vk := range validationKeys {
		if vk.KeyId == headerKid {
			found = true
		}
		k, err := jwk.Import(vk.Key)
		if err != nil {
			t.Fatalf("jwk from raw: %v", err)
		}
		if err := jwk.AssignKeyID(k); err != nil {
			t.Fatalf("assign key id: %v", err)
		}
		_ = k.Set(jwk.AlgorithmKey, vk.SigningAlgorithm)
		if err := set.AddKey(k); err != nil {
			t.Fatalf("add key: %v", err)
		}
	}
	if !found {
		t.Fatalf("header kid %q not present in validation key ids", headerKid)
	}

	pub, err := jwk.PublicSetOf(set)
	if err != nil {
		t.Fatalf("public set: %v", err)
	}
	if _, err := jwt.Parse([]byte(signed), jwt.WithKeySet(pub), jwt.WithValidate(false)); err != nil {
		t.Fatalf("validation key set did not verify the signed token: %v", err)
	}
}

// TestCreateTokenTypHeaderPerTokenType: a logout token is explicitly typed
// logout+jwt, while access and identity tokens keep their existing typ.
func TestCreateTokenTypHeaderPerTokenType(t *testing.T) {
	keys := NewKeyMaterialService(nil, nil, rs256Manager(), nil)
	creator := NewTokenCreationService(keys, test_common.NewStubClock(), config_options.NewWicketOptions(), nil)

	for tokenType, wantTyp := range map[string]string{
		TokenTypesLogoutToken:          "logout+jwt",
		wicket.TokenTypesAccessToken:   config_options.NewWicketOptions().AccessTokenJwtType,
		wicket.TokenTypesIdentityToken: "JWT",
	} {
		t.Run(tokenType, func(t *testing.T) {
			signed, err := creator.CreateToken(context.Background(), &storage_models.Token{
				Type:      tokenType,
				Issuer:    "https://issuer.wicket.test",
				Audiences: []string{"relying-party"},
				Lifetime:  60,
			})
			if err != nil {
				t.Fatalf("create token: %v", err)
			}
			msg, err := jws.Parse([]byte(signed))
			if err != nil {
				t.Fatalf("parse jws: %v", err)
			}
			typ, _ := msg.Signatures()[0].ProtectedHeaders().Type()
			if typ != wantTyp {
				t.Fatalf("typ = %q, want %q", typ, wantTyp)
			}
		})
	}
}
