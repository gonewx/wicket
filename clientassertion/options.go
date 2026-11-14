// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
)

// authenticationMethod is the token endpoint authentication method name of
// assertion based client authentication.
const authenticationMethod = "private_key_jwt"

// assertionType is the only accepted client_assertion_type value.
const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

const (
	maxClockSkew          = 10 * time.Minute
	maxAssertionLifetime  = time.Hour
	maxJwksCacheEntries   = 1024
	maxAssertionIdBytes   = 256
	maxLoggedKeyIdBytes   = 64
	minRsaModulusBits     = 2048
	maxNumericDateSeconds = 253402300799
)

// ErrAuthenticationUnavailable reports that client authentication could not
// be decided because a backing store failed: the replay registry, or the
// client store read by the secret, assertion and certificate authenticators
// (the store error is wrapped). It is neither a replay, an invalid client nor
// a successful authentication; endpoints answer it with a server error.
var ErrAuthenticationUnavailable = errors.New("client authentication temporarily unavailable")

// supportedSigningAlgorithms is the closed set of accepted signature
// algorithms. All of them are asymmetric.
var supportedSigningAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// SupportedSigningAlgorithms returns the closed set of signature algorithms
// an assertion may be signed with.
func SupportedSigningAlgorithms() []string {
	return slices.Clone(supportedSigningAlgorithms)
}

// Options configures assertion based client authentication. A zero field
// takes its default, see DefaultOptions.
type Options struct {
	// ClockSkew is the tolerated clock difference when time claims are judged.
	ClockSkew time.Duration
	// MaxAssertionLifetime bounds how far in the future exp may lie.
	MaxAssertionLifetime time.Duration
	// SigningAlgorithms lists the accepted signature algorithms, a subset of
	// SupportedSigningAlgorithms.
	SigningAlgorithms []string
	// MaxAssertionBytes bounds the length of an assertion.
	MaxAssertionBytes int
	// JwksFetchTimeout bounds one fetch of a JWK Set address.
	JwksFetchTimeout time.Duration
	// MaxJwksResponseBytes bounds the size of a fetched JWK Set.
	MaxJwksResponseBytes int64
	// JwksCacheLifetime is how long a fetched JWK Set is used.
	JwksCacheLifetime time.Duration
	// JwksMinRefreshInterval is the least time between two fetches of the
	// same JWK Set address.
	JwksMinRefreshInterval time.Duration
	// HTTPClient supplies the transport used to fetch JWK Sets. Only its
	// Transport is used; nil, or a nil Transport, selects a dedicated
	// transport with default TLS verification.
	HTTPClient *http.Client
	// AllowInsecureJwksUri permits http JWK Set addresses.
	AllowInsecureJwksUri bool
}

// DefaultOptions returns the defaults a zero field of Options takes.
func DefaultOptions() Options {
	return Options{
		ClockSkew:              60 * time.Second,
		MaxAssertionLifetime:   5 * time.Minute,
		SigningAlgorithms:      SupportedSigningAlgorithms(),
		MaxAssertionBytes:      16384,
		JwksFetchTimeout:       5 * time.Second,
		MaxJwksResponseBytes:   262144,
		JwksCacheLifetime:      time.Hour,
		JwksMinRefreshInterval: 60 * time.Second,
	}
}

// withDefaults returns a copy whose zero fields carry their defaults.
func (o Options) withDefaults() Options {
	defaults := DefaultOptions()
	if o.ClockSkew == 0 {
		o.ClockSkew = defaults.ClockSkew
	}
	if o.MaxAssertionLifetime == 0 {
		o.MaxAssertionLifetime = defaults.MaxAssertionLifetime
	}
	if len(o.SigningAlgorithms) == 0 {
		o.SigningAlgorithms = defaults.SigningAlgorithms
	} else {
		o.SigningAlgorithms = slices.Clone(o.SigningAlgorithms)
	}
	if o.MaxAssertionBytes == 0 {
		o.MaxAssertionBytes = defaults.MaxAssertionBytes
	}
	if o.JwksFetchTimeout == 0 {
		o.JwksFetchTimeout = defaults.JwksFetchTimeout
	}
	if o.MaxJwksResponseBytes == 0 {
		o.MaxJwksResponseBytes = defaults.MaxJwksResponseBytes
	}
	if o.JwksCacheLifetime == 0 {
		o.JwksCacheLifetime = defaults.JwksCacheLifetime
	}
	if o.JwksMinRefreshInterval == 0 {
		o.JwksMinRefreshInterval = defaults.JwksMinRefreshInterval
	}
	return o
}

// Validate rejects options that cannot be served: a negative duration or
// size, a signing algorithm outside SupportedSigningAlgorithms or listed
// twice, a clock skew above ten minutes, or an assertion lifetime above one
// hour.
func (o Options) Validate() error {
	durations := []struct {
		name  string
		value time.Duration
	}{
		{"ClockSkew", o.ClockSkew},
		{"MaxAssertionLifetime", o.MaxAssertionLifetime},
		{"JwksFetchTimeout", o.JwksFetchTimeout},
		{"JwksCacheLifetime", o.JwksCacheLifetime},
		{"JwksMinRefreshInterval", o.JwksMinRefreshInterval},
	}
	for _, duration := range durations {
		if duration.value < 0 {
			return fmt.Errorf("%s must not be negative", duration.name)
		}
	}
	if o.MaxAssertionBytes < 0 {
		return errors.New("MaxAssertionBytes must not be negative")
	}
	if o.MaxJwksResponseBytes < 0 {
		return errors.New("MaxJwksResponseBytes must not be negative")
	}
	if o.ClockSkew > maxClockSkew {
		return fmt.Errorf("ClockSkew must not exceed %s", maxClockSkew)
	}
	if o.MaxAssertionLifetime > maxAssertionLifetime {
		return fmt.Errorf("MaxAssertionLifetime must not exceed %s", maxAssertionLifetime)
	}
	seen := make(map[string]struct{}, len(o.SigningAlgorithms))
	for _, algorithm := range o.SigningAlgorithms {
		if !slices.Contains(supportedSigningAlgorithms, algorithm) {
			return fmt.Errorf("SigningAlgorithms holds unsupported algorithm %q", algorithm)
		}
		if _, duplicate := seen[algorithm]; duplicate {
			return fmt.Errorf("SigningAlgorithms lists %q more than once", algorithm)
		}
		seen[algorithm] = struct{}{}
	}
	return nil
}

// currentOptions reads the options in force for one call. A nil source
// stands for the defaults.
func currentOptions(source func() Options) Options {
	if source == nil {
		return DefaultOptions()
	}
	return source().withDefaults()
}
