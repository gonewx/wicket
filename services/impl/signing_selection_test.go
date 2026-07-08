// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/keymgmt"
	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/tokens"
)

type fakeSigningStore struct {
	credential *tokens.SigningCredentials
	err        error
}

func (s fakeSigningStore) GetSigningCredentials() (*tokens.SigningCredentials, error) {
	return s.credential, s.err
}

type fakeValidationStore struct {
	keys []*core_models.SecurityKeyInfo
	err  error
}

func (s fakeValidationStore) GetValidationKeys() ([]*core_models.SecurityKeyInfo, error) {
	return s.keys, s.err
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) }

type reversibleProvider struct{}

func (reversibleProvider) Create(string) dp.DataProtector { return reversibleProtector{} }

type reversibleProtector struct{}

func (reversibleProtector) Protect(data []byte) []byte { return append([]byte("p:"), data...) }
func (reversibleProtector) Unprotect(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("corrupt")
	}
	return data[2:], nil
}

func hostCredential(t *testing.T, algorithm, kid string) *tokens.SigningCredentials {
	t.Helper()
	credential, err := tokens.NewSigningCredentials("host-key", tokens.WithAlgorithm(algorithm), tokens.WithKid(kid))
	if err != nil {
		t.Fatalf("build host credential: %v", err)
	}
	return credential
}

func enabledManager(store keymgmt.RecordStore) *keymgmt.Manager {
	return keymgmt.NewManager(keymgmt.Config{
		Enabled:            true,
		AutoCreate:         true,
		RotationInterval:   time.Hour,
		ActivationLeadTime: 10 * time.Minute,
		RetentionDuration:  20 * time.Minute,
		AllowedAlgorithms:  []string{keymgmt.AlgES256},
		DefaultAlgorithm:   keymgmt.AlgES256,
		CacheTTL:           time.Minute,
		ClockSkew:          time.Minute,
	}, store, reversibleProvider{}, fixedClock{}, rand.Reader, nil)
}

func TestResolveAllowedAlgorithms(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		requested     []string
		configAllowed []string
		wantEmpty     bool
		wantUnrest    bool
		wantMember    string
		wantNonMember string
	}{
		"no limits is unrestricted": {
			wantUnrest: true,
		},
		"config only": {
			configAllowed: []string{"ES256"},
			wantMember:    "ES256",
			wantNonMember: "RS256",
		},
		"request only": {
			requested:     []string{"RS256"},
			wantMember:    "RS256",
			wantNonMember: "ES256",
		},
		"intersection": {
			requested:     []string{"RS256", "ES256"},
			configAllowed: []string{"ES256", "ES384"},
			wantMember:    "ES256",
			wantNonMember: "RS256",
		},
		"empty intersection": {
			requested:     []string{"RS256"},
			configAllowed: []string{"ES256"},
			wantEmpty:     true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			set, unrestricted, empty := resolveAllowedAlgorithms(tc.requested, tc.configAllowed)
			if empty != tc.wantEmpty {
				t.Fatalf("emptyIntersection = %v, want %v", empty, tc.wantEmpty)
			}
			if unrestricted != tc.wantUnrest {
				t.Fatalf("unrestricted = %v, want %v", unrestricted, tc.wantUnrest)
			}
			if tc.wantMember != "" && !unrestricted && !set[tc.wantMember] {
				t.Fatalf("expected %q to be allowed", tc.wantMember)
			}
			if tc.wantNonMember != "" && !unrestricted && set[tc.wantNonMember] {
				t.Fatalf("expected %q to be disallowed", tc.wantNonMember)
			}
		})
	}
}

func TestKeyMaterialServiceHostSelection(t *testing.T) {
	t.Parallel()

	svc := NewKeyMaterialService(
		[]storage.SigningCredentialStore{
			fakeSigningStore{credential: hostCredential(t, "ES256", "kid-b")},
			fakeSigningStore{credential: hostCredential(t, "RS256", "kid-a")},
		},
		nil, nil, nil,
	)

	// Empty request: no config limit in host mode, tiebreak by public id ascending.
	credential, err := svc.GetSigningCredentials(nil)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if credential.Kid != "kid-a" {
		t.Fatalf("selected kid = %q, want kid-a (lexicographic tiebreak)", credential.Kid)
	}

	// Restrict to ES256: only the ES256 host credential qualifies.
	credential, err = svc.GetSigningCredentials([]string{"ES256"})
	if err != nil {
		t.Fatalf("select ES256: %v", err)
	}
	if credential.Algorithm != "ES256" || credential.Kid != "kid-b" {
		t.Fatalf("selected %q/%q, want ES256/kid-b", credential.Algorithm, credential.Kid)
	}

	// Request an algorithm no host store offers: explicit error.
	if _, err := svc.GetSigningCredentials([]string{"ES512"}); err == nil {
		t.Fatal("expected error for unavailable algorithm")
	}
}

func TestKeyMaterialServiceAutoManagerSelection(t *testing.T) {
	t.Parallel()

	manager := enabledManager(keymgmt.NewMemoryRecordStore())

	// Host signing store must be ignored when the manager is enabled.
	svc := NewKeyMaterialService(
		[]storage.SigningCredentialStore{fakeSigningStore{credential: hostCredential(t, "RS256", "host")}},
		nil, manager, nil,
	)

	credential, err := svc.GetSigningCredentials(nil)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if credential.Algorithm != keymgmt.AlgES256 {
		t.Fatalf("selected algorithm %q, want ES256 from the auto manager", credential.Algorithm)
	}
	if credential.Kid == "host" {
		t.Fatal("host signing store must not participate when the manager is enabled")
	}

	// The manager's allowed set intersected with a disjoint request is empty.
	if _, err := svc.GetSigningCredentials([]string{"RS256"}); err == nil {
		t.Fatal("expected empty-intersection error against the manager allowed set")
	}
}

func TestKeyMaterialServiceValidationErrorIsolation(t *testing.T) {
	t.Parallel()

	good := &core_models.SecurityKeyInfo{SigningAlgorithm: "ES256", KeyId: "good"}
	svc := NewKeyMaterialService(nil, []storage.ValidationKeysStore{
		fakeValidationStore{err: errors.New("store down")},
		fakeValidationStore{keys: []*core_models.SecurityKeyInfo{good}},
	}, nil, nil)

	keys, err := svc.GetValidationKeys()
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyId != "good" {
		t.Fatalf("isolation failed: got %d keys", len(keys))
	}
}

func TestKeyMaterialServiceValidationDeduplicatesKeyId(t *testing.T) {
	t.Parallel()

	dup := &core_models.SecurityKeyInfo{SigningAlgorithm: "ES256", KeyId: "dup"}
	svc := NewKeyMaterialService(nil, []storage.ValidationKeysStore{
		fakeValidationStore{keys: []*core_models.SecurityKeyInfo{dup}},
		fakeValidationStore{keys: []*core_models.SecurityKeyInfo{dup}},
	}, nil, nil)

	keys, err := svc.GetValidationKeys()
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("duplicate key id not omitted: got %d keys", len(keys))
	}
}

func TestKeyMaterialServiceValidationFailsClosedWhenNothingSurvives(t *testing.T) {
	t.Parallel()

	svc := NewKeyMaterialService(nil, []storage.ValidationKeysStore{
		fakeValidationStore{err: errors.New("store down")},
	}, nil, nil)

	if _, err := svc.GetValidationKeys(); err == nil {
		t.Fatal("expected fail-closed error when every source errored")
	}
}
