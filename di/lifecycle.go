// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package di owns the composition root: the container that wires the
// store seams a host injects through ServerConfig, the lazy wrappers that
// defer seam reads until first use, and the generated root container.
//
// # Lifecycle contract
//
// Every lazy store wrapper implements io.Closer. Close releases a host
// adapter that was already materialized through the wrapper: when the
// adapter itself implements io.Closer, Close forwards the call and returns
// its error; otherwise Close is a no-op returning nil. A wrapper whose
// seam was never materialized returns nil without constructing anything —
// closing is not a use, so it must not read the seam and must not trigger
// the in-memory fallback warning.
//
// The generated root container tracks the wrappers in construction order
// and releases them through Root.Close in LIFO (reverse-construction)
// order. Root.Close is idempotent: the second call returns the cached
// result of the first, and every resolve after Close panics with
// godi.ErrProviderClosed.
//
// The host owns the close sequence: it must stop using the container and
// its resolved adapters before calling Root.Close. Using an adapter while
// the container is closing is a host error and is not synchronized.
package di

import (
	"io"
	"log/slog"

	"github.com/gonewx/wicket/services"
)

// The constructors below follow the generator's discovery convention for
// Form A registrations: godi-gen looks up "New" + the exact implementation
// type name (godi-gen main.go:359), so a wrapper type named lazyXxx needs
// NewlazyXxx — the type names themselves are fixed by the lazy-seam design
// in inmemory.go, and the exported constructor is the only seam surface.
//
// NewlazyPersistedGrantStore returns the lazy wrapper the generated root
// assembles for the persisted grant store seam. The wrapper reads the
// ServerConfig seam on first use and falls back to the in-memory store
// with a warning when the host did not inject one.
func NewlazyPersistedGrantStore(cfg *ServerConfig, logger *slog.Logger) *lazyPersistedGrantStore {
	return &lazyPersistedGrantStore{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyPersistedGrantStore) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazyDeviceFlowStore returns the lazy wrapper for the device flow
// store seam.
func NewlazyDeviceFlowStore(cfg *ServerConfig, logger *slog.Logger) *lazyDeviceFlowStore {
	return &lazyDeviceFlowStore{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyDeviceFlowStore) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazyBackchannelAuthenticationRequestStore returns the lazy wrapper
// for the backchannel authentication request store seam.
func NewlazyBackchannelAuthenticationRequestStore(cfg *ServerConfig, logger *slog.Logger) *lazyBackchannelAuthenticationRequestStore {
	return &lazyBackchannelAuthenticationRequestStore{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyBackchannelAuthenticationRequestStore) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazyAuthorizationCodeStore returns the lazy wrapper for the
// authorization code store seam.
func NewlazyAuthorizationCodeStore(cfg *ServerConfig, logger *slog.Logger) *lazyAuthorizationCodeStore {
	return &lazyAuthorizationCodeStore{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyAuthorizationCodeStore) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazyRefreshTokenStore returns the lazy wrapper for the refresh token
// store seam.
func NewlazyRefreshTokenStore(cfg *ServerConfig, logger *slog.Logger) *lazyRefreshTokenStore {
	return &lazyRefreshTokenStore{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyRefreshTokenStore) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazyReferenceTokenStore returns the lazy wrapper for the reference
// token store seam.
func NewlazyReferenceTokenStore(cfg *ServerConfig, logger *slog.Logger) *lazyReferenceTokenStore {
	return &lazyReferenceTokenStore{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyReferenceTokenStore) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazyUserConsentStore returns the lazy wrapper for the user consent
// store seam.
func NewlazyUserConsentStore(cfg *ServerConfig, logger *slog.Logger) *lazyUserConsentStore {
	return &lazyUserConsentStore{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyUserConsentStore) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazySessionStore returns the lazy wrapper for the session store
// seam. The clock feeds the in-memory fallback store.
func NewlazySessionStore(cfg *ServerConfig, logger *slog.Logger, clock services.SystemClock) *lazySessionStore {
	return &lazySessionStore{cfg: cfg, logger: logger, clock: clock}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazySessionStore) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazyDistributedCache returns the lazy wrapper for the distributed
// cache seam.
func NewlazyDistributedCache(cfg *ServerConfig, logger *slog.Logger) *lazyDistributedCache {
	return &lazyDistributedCache{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyDistributedCache) Close() error {
	return closeMaterialized(s.impl)
}

// NewLazyRecordStore returns the lazy wrapper for the key record store
// seam.
func NewlazyRecordStore(cfg *ServerConfig, logger *slog.Logger) *lazyRecordStore {
	return &lazyRecordStore{cfg: cfg, logger: logger}
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract.
func (s *lazyRecordStore) Close() error {
	return closeMaterialized(s.impl)
}

// closeMaterialized forwards Close to an adapter that implements
// io.Closer. A nil adapter (unmaterialized seam) or an adapter without a
// Close method releases nothing and returns nil.
func closeMaterialized(adapter any) error {
	if closer, ok := adapter.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

var _ io.Closer = (*lazyPersistedGrantStore)(nil)
var _ io.Closer = (*lazyDeviceFlowStore)(nil)
var _ io.Closer = (*lazyBackchannelAuthenticationRequestStore)(nil)
var _ io.Closer = (*lazyAuthorizationCodeStore)(nil)
var _ io.Closer = (*lazyRefreshTokenStore)(nil)
var _ io.Closer = (*lazyReferenceTokenStore)(nil)
var _ io.Closer = (*lazyUserConsentStore)(nil)
var _ io.Closer = (*lazySessionStore)(nil)
var _ io.Closer = (*lazyDistributedCache)(nil)
var _ io.Closer = (*lazyRecordStore)(nil)
