// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket/replay"
)

type recordingRegistry struct {
	key       string
	expiresAt time.Time
	calls     int
	err       error
}

func (r *recordingRegistry) Register(_ context.Context, key string, expiresAt time.Time) error {
	r.calls++
	r.key, r.expiresAt = key, expiresAt
	return r.err
}

func (r *recordingRegistry) RemoveExpired(context.Context, time.Time) (int, error) { return 0, nil }

func TestRegistrationExpiry(t *testing.T) {
	t.Parallel()
	options := Options{ProofLifetime: 30 * time.Second, ClockSkew: 10 * time.Second}
	cases := map[string]struct {
		iat  time.Time
		want time.Time
	}{
		"fresh proof uses iat plus lifetime": {testNow.Add(-5 * time.Second), testNow.Add(35 * time.Second)},
		"proof from the future":              {testNow.Add(8 * time.Second), testNow.Add(48 * time.Second)},
		"old proof uses now":                 {testNow.Add(-38 * time.Second), testNow.Add(10 * time.Second)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := RegistrationExpiry(Proof{IssuedAt: tc.iat}, options, testNow)
			if !got.Equal(tc.want) {
				t.Fatalf("expiry %s, want %s", got, tc.want)
			}
		})
	}
	if got := RegistrationExpiry(Proof{IssuedAt: testNow}, Options{}, testNow); !got.Equal(testNow.Add(2 * time.Minute)) {
		t.Fatalf("defaults: expiry %s", got)
	}
}

func TestRegister(t *testing.T) {
	t.Parallel()
	proof := Proof{Thumbprint: "tp", JwtId: "jti", IssuedAt: testNow}
	wantKey, err := replay.Key(replay.PurposeDPoPProof(), "tp", "jti")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("first use", func(t *testing.T) {
		t.Parallel()
		registry := &recordingRegistry{}
		if err := Register(context.Background(), registry, proof, Options{}, testNow); err != nil {
			t.Fatal(err)
		}
		if registry.key != wantKey || !registry.expiresAt.Equal(RegistrationExpiry(proof, Options{}, testNow)) {
			t.Fatalf("registered %q until %s", registry.key, registry.expiresAt)
		}
	})
	t.Run("key qualifier is the thumbprint", func(t *testing.T) {
		t.Parallel()
		registry := &recordingRegistry{}
		other := proof
		other.Thumbprint = "another"
		if err := Register(context.Background(), registry, other, Options{}, testNow); err != nil {
			t.Fatal(err)
		}
		if registry.key == wantKey {
			t.Fatal("the key does not depend on the thumbprint")
		}
		assertion, _ := replay.Key(replay.PurposeClientAssertion(), "tp", "jti")
		if wantKey == assertion {
			t.Fatal("the key does not depend on the purpose")
		}
	})
	t.Run("replay", func(t *testing.T) {
		t.Parallel()
		registry := &recordingRegistry{err: replay.ErrDuplicateHandle}
		err := Register(context.Background(), registry, proof, Options{}, testNow)
		if !errors.Is(err, ErrReplayedProof) || !errors.Is(err, replay.ErrDuplicateHandle) || errors.Is(err, ErrRegistrationUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("registry failure", func(t *testing.T) {
		t.Parallel()
		cause := errors.New("down")
		registry := &recordingRegistry{err: cause}
		err := Register(context.Background(), registry, proof, Options{}, testNow)
		if !errors.Is(err, ErrRegistrationUnavailable) || !errors.Is(err, cause) || errors.Is(err, ErrReplayedProof) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("key cannot be derived", func(t *testing.T) {
		t.Parallel()
		registry := &recordingRegistry{}
		err := Register(context.Background(), registry, Proof{Thumbprint: "tp"}, Options{}, testNow)
		if !errors.Is(err, ErrRegistrationUnavailable) || !errors.Is(err, replay.ErrInvalidKeyInput) || registry.calls != 0 {
			t.Fatalf("err = %v, calls = %d", err, registry.calls)
		}
	})
	t.Run("no registry", func(t *testing.T) {
		t.Parallel()
		if err := Register(context.Background(), nil, proof, Options{}, testNow); !errors.Is(err, ErrRegistrationUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
}
