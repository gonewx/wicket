// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"

	"github.com/gonewx/wicket/storage"
)

// The client registration store seam is feature-required: it must be
// injected while a feature that depends on it is enabled, and
// AllowInMemoryFallback does not exempt it. The seam has no fallback
// declaration of its own: a host that wants the in-memory store injects
// storage/memory.NewMemoryClientRegistrationStore() explicitly, so the read
// path and the registration path always share one value. The container never
// registers the writable port; a dependent feature reads it through
// clientRegistrationStoreForFeature.

// clientRegistrationStoreSeamName is how the seam is named in failures.
const clientRegistrationStoreSeamName = "client registration store"

// SetClientRegistrationStore injects the host's client registration store.
// The same value also serves the client store seam: the container wraps it
// in the configuration-validating decorator for every client read, and CORS
// decisions read its origin lookup. The value must implement
// storage.ClientOriginLookup, and it excludes SetClientStore, SetClients and
// SetClientsProvider; Freeze enforces both.
func (c *ServerConfig) SetClientRegistrationStore(store storage.ClientRegistrationStore) {
	c.clientRegistrationStore = store
}

// enableClientRegistrationDependentFeature records that a feature depending
// on the client registration store is enabled. The record keeps
// first-enabled order and holds each name once; the seam is required exactly
// when the record is non-empty.
func (c *ServerConfig) enableClientRegistrationDependentFeature(name string) {
	if c.clientRegistrationDependentFeatureEnabled(name) {
		return
	}
	c.clientRegistrationDependentFeatures = append(c.clientRegistrationDependentFeatures, name)
}

// clientRegistrationDependentFeatureEnabled reports whether the named feature
// was recorded by enableClientRegistrationDependentFeature.
func (c *ServerConfig) clientRegistrationDependentFeatureEnabled(name string) bool {
	if c == nil {
		return false
	}
	for _, enabled := range c.clientRegistrationDependentFeatures {
		if enabled == name {
			return true
		}
	}
	return false
}

// clientRegistrationStoreRequired reports whether a dependent feature is
// enabled, which is the condition of the feature-required seam.
func (c *ServerConfig) clientRegistrationStoreRequired() bool {
	return c != nil && len(c.clientRegistrationDependentFeatures) > 0
}

// clientRegistrationStoreForFeature returns the injected client registration
// store to a dependent feature. It fails while no dependent feature is
// enabled, so no code path reaches the writable port unless the condition
// holds, and it fails when the host injected none.
func (c *ServerConfig) clientRegistrationStoreForFeature() (storage.ClientRegistrationStore, error) {
	if !c.clientRegistrationStoreRequired() {
		return nil, fmt.Errorf("store seam %q used although no feature that depends on it is enabled", clientRegistrationStoreSeamName)
	}
	if c.clientRegistrationStore == nil {
		return nil, fmt.Errorf("store seam %q not injected by host", clientRegistrationStoreSeamName)
	}
	return c.clientRegistrationStore, nil
}

// requireClientRegistrationStoreSeam checks an injected client registration
// store: it is the only client source, and it answers CORS origin lookups
// from the same data.
func (c *ServerConfig) requireClientRegistrationStoreSeam() {
	if c.clientRegistrationStore == nil {
		return
	}
	if c.clientStore != nil {
		panic("client registration store injected by host together with SetClientStore; use one of them")
	}
	if c.clientsProvider != nil {
		panic("client registration store injected by host together with SetClients or SetClientsProvider; use one of them")
	}
	if _, ok := c.clientRegistrationStore.(storage.ClientOriginLookup); !ok {
		panic(fmt.Sprintf("client registration store injected by host (%T) does not implement storage.ClientOriginLookup, which CORS decisions require", c.clientRegistrationStore))
	}
}
