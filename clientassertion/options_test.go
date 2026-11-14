// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"slices"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	got := DefaultOptions()
	if got.ClockSkew != 60*time.Second || got.MaxAssertionLifetime != 5*time.Minute ||
		got.MaxAssertionBytes != 16384 || got.JwksFetchTimeout != 5*time.Second ||
		got.MaxJwksResponseBytes != 262144 || got.JwksCacheLifetime != time.Hour ||
		got.JwksMinRefreshInterval != 60*time.Second || got.HTTPClient != nil || got.AllowInsecureJwksUri {
		t.Fatalf("unexpected defaults: %+v", got)
	}
	want := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
	if !slices.Equal(got.SigningAlgorithms, want) || !slices.Equal(SupportedSigningAlgorithms(), want) {
		t.Fatalf("unexpected algorithms: %v", got.SigningAlgorithms)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("defaults do not validate: %v", err)
	}
	if err := (Options{}).Validate(); err != nil {
		t.Fatalf("zero options do not validate: %v", err)
	}
}

func TestSupportedSigningAlgorithmsReturnsACopy(t *testing.T) {
	SupportedSigningAlgorithms()[0] = "none"
	if SupportedSigningAlgorithms()[0] != "RS256" {
		t.Fatalf("the closed set was modified through a returned slice")
	}
}

func TestOptionsValidate(t *testing.T) {
	cases := map[string]Options{
		"negative skew":             {ClockSkew: -time.Second},
		"negative lifetime":         {MaxAssertionLifetime: -time.Second},
		"negative fetch timeout":    {JwksFetchTimeout: -time.Second},
		"negative cache lifetime":   {JwksCacheLifetime: -time.Second},
		"negative refresh interval": {JwksMinRefreshInterval: -time.Second},
		"negative assertion size":   {MaxAssertionBytes: -1},
		"negative response size":    {MaxJwksResponseBytes: -1},
		"skew over ten minutes":     {ClockSkew: 10*time.Minute + time.Second},
		"lifetime over one hour":    {MaxAssertionLifetime: time.Hour + time.Second},
		"none":                      {SigningAlgorithms: []string{"none"}},
		"symmetric":                 {SigningAlgorithms: []string{"RS256", "HS256"}},
		"unknown":                   {SigningAlgorithms: []string{"EdDSA"}},
		"duplicate":                 {SigningAlgorithms: []string{"RS256", "RS256"}},
	}
	for name, options := range cases {
		if err := options.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	accepted := Options{ClockSkew: 10 * time.Minute, MaxAssertionLifetime: time.Hour, SigningAlgorithms: []string{"PS256", "ES256"}}
	if err := accepted.Validate(); err != nil {
		t.Fatalf("bounds rejected: %v", err)
	}
}
