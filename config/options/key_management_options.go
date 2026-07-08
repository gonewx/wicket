// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

import (
	"time"

	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/keymgmt"
)

// KeyManagementOptions configures automatic signing key management. It is off by
// default; when enabled the manager maintains signing and validation material.
// Duration zero values receive conservative defaults inside the manager. The
// injected seams (storage, protector, clock, entropy) fall back to safe defaults
// when left nil. Business packages do not read the environment; a host loads
// configuration and injects it here.
type KeyManagementOptions struct {
	// Enabled turns on automatic key management.
	Enabled bool
	// AutoCreate distinguishes host-unset (nil, defaults to on when enabled) from
	// an explicit host decision. An explicit false means no key is created when
	// none is active, so startup surfaces a configuration error instead.
	AutoCreate *bool
	// RotationInterval is the signing lifetime of an active key.
	RotationInterval time.Duration
	// ActivationLeadTime is the candidate warm-up window before activation.
	ActivationLeadTime time.Duration
	// RetentionDuration is how long a retired-from-signing key stays published so
	// already-issued tokens remain verifiable. Covering the maximum token
	// lifetime plus clock skew is a host responsibility.
	RetentionDuration time.Duration
	// AllowedAlgorithms is the explicit set of JWA algorithms permitted for
	// signing selection and creation.
	AllowedAlgorithms []string
	// DefaultAlgorithm is the algorithm used to create new keys; it must be a
	// member of AllowedAlgorithms.
	DefaultAlgorithm string
	// CacheTTL bounds how long a key set snapshot is reused.
	CacheTTL time.Duration
	// ClockSkew widens the JWKS publish window so skewed verifiers resolve a kid.
	ClockSkew time.Duration
	// AllowMultipleActive permits more than one active key per purpose.
	AllowMultipleActive bool
	// StorageProvider persists key records; nil uses an in-memory store.
	StorageProvider keymgmt.RecordStore
	// Protector protects private key material; nil uses the default provider.
	Protector dp.DataProtectionProvider
	// Clock is the injected time source; nil uses the default clock.
	Clock keymgmt.Clock
	// Entropy is the injected random source; nil uses crypto/rand.
	Entropy keymgmt.Entropy
}

func NewKeyManagementOptions() *KeyManagementOptions {
	return &KeyManagementOptions{
		Enabled:           false,
		AllowedAlgorithms: []string{keymgmt.AlgRS256},
		DefaultAlgorithm:  keymgmt.AlgRS256,
	}
}
