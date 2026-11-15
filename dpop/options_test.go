// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"slices"
	"testing"
	"time"

	"github.com/gonewx/wicket/clientassertion"
)

func TestDefaultOptions(t *testing.T) {
	t.Parallel()
	defaults := DefaultOptions()
	if !slices.Equal(defaults.SigningAlgorithms, clientassertion.SupportedSigningAlgorithms()) {
		t.Fatalf("algorithms %v", defaults.SigningAlgorithms)
	}
	if defaults.ProofLifetime != 60*time.Second || defaults.ClockSkew != 60*time.Second || defaults.NonceLifetime != 5*time.Minute || defaults.RequireNonce {
		t.Fatalf("defaults %+v", defaults)
	}
	defaults.SigningAlgorithms[0] = "changed"
	if DefaultOptions().SigningAlgorithms[0] == "changed" {
		t.Fatal("DefaultOptions shares its algorithm list")
	}
	if err := defaults.Validate(); err == nil {
		t.Fatal("a changed algorithm list still validates")
	}
	if err := DefaultOptions().Validate(); err != nil {
		t.Fatalf("defaults do not validate: %v", err)
	}
}

func TestWithDefaults(t *testing.T) {
	t.Parallel()
	filled := Options{}.withDefaults()
	if !slices.Equal(filled.SigningAlgorithms, DefaultOptions().SigningAlgorithms) || filled.ProofLifetime != time.Minute || filled.ClockSkew != time.Minute || filled.NonceLifetime != 5*time.Minute {
		t.Fatalf("filled %+v", filled)
	}
	algorithms := []string{"ES256"}
	kept := Options{SigningAlgorithms: algorithms, ProofLifetime: time.Second, ClockSkew: 2 * time.Second}.withDefaults()
	algorithms[0] = "RS256"
	if !slices.Equal(kept.SigningAlgorithms, []string{"ES256"}) || kept.ProofLifetime != time.Second || kept.ClockSkew != 2*time.Second {
		t.Fatalf("kept %+v", kept)
	}
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		options Options
		valid   bool
	}{
		"zero":                     {Options{}, true},
		"subset":                   {Options{SigningAlgorithms: []string{"ES256", "PS256"}}, true},
		"upper bounds":             {Options{ProofLifetime: 10 * time.Minute, ClockSkew: 10 * time.Minute, NonceLifetime: 10 * time.Minute}, true},
		"nonce lifetime negative":  {Options{NonceLifetime: -time.Second}, false},
		"nonce lifetime too long":  {Options{NonceLifetime: 10*time.Minute + time.Second}, false},
		"nonce required":           {Options{RequireNonce: true}, true},
		"none":                     {Options{SigningAlgorithms: []string{"none"}}, false},
		"symmetric":                {Options{SigningAlgorithms: []string{"HS256"}}, false},
		"EdDSA":                    {Options{SigningAlgorithms: []string{"EdDSA"}}, false},
		"duplicate":                {Options{SigningAlgorithms: []string{"ES256", "ES256"}}, false},
		"negative lifetime":        {Options{ProofLifetime: -time.Second}, false},
		"negative skew":            {Options{ClockSkew: -time.Second}, false},
		"lifetime above ten min":   {Options{ProofLifetime: 10*time.Minute + time.Second}, false},
		"clock skew above ten min": {Options{ClockSkew: 10*time.Minute + time.Second}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := tc.options.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, valid = %v", err, tc.valid)
			}
		})
	}
}
