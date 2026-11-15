// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gonewx/wicket/clientassertion"
)

const (
	// maxProofLifetime bounds ProofLifetime.
	maxProofLifetime = 10 * time.Minute
	// maxClockSkew bounds ClockSkew.
	maxClockSkew = 10 * time.Minute
	// maxNonceLifetime bounds NonceLifetime.
	maxNonceLifetime = 10 * time.Minute
	// maxProofIdBytes bounds the length of the jti claim.
	maxProofIdBytes = 256
	// maxProofNonceBytes bounds the length of the nonce claim.
	maxProofNonceBytes = 512
	// maxProofBytes bounds the length of one proof.
	maxProofBytes = 16384
	// minRsaModulusBits is the least accepted RSA modulus size.
	minRsaModulusBits = 2048
	// maxRsaModulusBits is the largest accepted RSA modulus size.
	maxRsaModulusBits = 8192
	// maxRsaPublicExponent is the largest accepted RSA public exponent.
	maxRsaPublicExponent = 1<<31 - 1
	// maxNumericDateSeconds is the largest accepted iat value.
	maxNumericDateSeconds = 253402300799
)

// Options configures proof verification. A zero field takes its default, see
// DefaultOptions.
type Options struct {
	// SigningAlgorithms lists the accepted proof signature algorithms, a
	// subset of the asymmetric algorithms clientassertion supports. It is
	// also what discovery advertises under dpop_signing_alg_values_supported.
	SigningAlgorithms []string
	// ProofLifetime is how long after its iat a proof is accepted.
	ProofLifetime time.Duration
	// ClockSkew is the tolerated clock difference when iat or a server
	// nonce is judged.
	ClockSkew time.Duration
	// RequireNonce makes the token endpoint demand a server nonce in every
	// proof (RFC 9449 section 8). It is off by default; once on, the host
	// has to inject the nonce key source.
	RequireNonce bool
	// NonceLifetime is how long after it was issued a server nonce is
	// accepted. It only matters while RequireNonce is set.
	NonceLifetime time.Duration
}

// DefaultOptions returns the defaults a zero field of Options takes.
func DefaultOptions() Options {
	return Options{
		SigningAlgorithms: clientassertion.SupportedSigningAlgorithms(),
		ProofLifetime:     60 * time.Second,
		ClockSkew:         60 * time.Second,
		NonceLifetime:     5 * time.Minute,
	}
}

// withDefaults returns a copy whose zero fields carry their defaults.
func (o Options) withDefaults() Options {
	defaults := DefaultOptions()
	if len(o.SigningAlgorithms) == 0 {
		o.SigningAlgorithms = defaults.SigningAlgorithms
	} else {
		o.SigningAlgorithms = slices.Clone(o.SigningAlgorithms)
	}
	if o.ProofLifetime == 0 {
		o.ProofLifetime = defaults.ProofLifetime
	}
	if o.ClockSkew == 0 {
		o.ClockSkew = defaults.ClockSkew
	}
	if o.NonceLifetime == 0 {
		o.NonceLifetime = defaults.NonceLifetime
	}
	return o
}

// Validate rejects options that cannot be served: a signing algorithm that
// clientassertion does not support or that is listed twice, a negative
// duration, or a proof lifetime, clock skew or nonce lifetime above ten
// minutes. An empty algorithm list is valid and stands for the default list.
func (o Options) Validate() error {
	if o.ProofLifetime < 0 {
		return errors.New("ProofLifetime must not be negative")
	}
	if o.ClockSkew < 0 {
		return errors.New("ClockSkew must not be negative")
	}
	if o.NonceLifetime < 0 {
		return errors.New("NonceLifetime must not be negative")
	}
	if o.ProofLifetime > maxProofLifetime {
		return fmt.Errorf("ProofLifetime must not exceed %s", maxProofLifetime)
	}
	if o.ClockSkew > maxClockSkew {
		return fmt.Errorf("ClockSkew must not exceed %s", maxClockSkew)
	}
	if o.NonceLifetime > maxNonceLifetime {
		return fmt.Errorf("NonceLifetime must not exceed %s", maxNonceLifetime)
	}
	supported := clientassertion.SupportedSigningAlgorithms()
	seen := make(map[string]struct{}, len(o.SigningAlgorithms))
	for _, algorithm := range o.SigningAlgorithms {
		if !slices.Contains(supported, algorithm) {
			return fmt.Errorf("SigningAlgorithms holds unsupported algorithm %q", algorithm)
		}
		if _, duplicate := seen[algorithm]; duplicate {
			return fmt.Errorf("SigningAlgorithms lists %q more than once", algorithm)
		}
		seen[algorithm] = struct{}{}
	}
	return nil
}
