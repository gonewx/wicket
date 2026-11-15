// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"

	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/pushedauth"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
)

// Pushed authorization requests (RFC 9126) depend on two seams, both
// feature-required while pushed authorization is enabled and neither exempted
// by AllowInMemoryFallback:
//
//   - the pushed authorization request store. It has no fallback
//     declaration: a host that wants the in-memory store injects
//     storage/memory.NewMemoryPushedAuthorizationRequestStore() explicitly.
//   - the pushed authorization data protection provider. It never has a
//     fallback, and it must be a real protection: the default
//     services/impl.DataProtectionProvider only encodes, so Freeze rejects
//     it whether or not pushed authorization is enabled. The protector is
//     only ever created with storage.PushedAuthorizationRequestPurpose.
//
// Neither seam is registered in the container, and the container's
// dp.DataProtectionProvider binding (used by key management and message
// cookies) is unaffected by them. Pushed authorization is enabled through
// enablePushedAuthorization; the feature reads the seams through
// pushedAuthorizationRequestStoreForFeature and
// pushedAuthorizationProtectorForFeature, which fail while it is disabled.

// Seam names as failures report them.
const (
	pushedAuthorizationRequestStoreSeamName   = "pushed authorization request store"
	pushedAuthorizationDataProtectionSeamName = "pushed authorization data protection"
)

// SetPushedAuthorizationRequestStoreProvider installs the provider of the
// host's pushed authorization request store. The provider is called at most
// once, on the first use of the store by the enabled feature.
func (c *ServerConfig) SetPushedAuthorizationRequestStoreProvider(provider func() storage.PushedAuthorizationRequestStore) {
	c.pushedAuthorizationRequestStoreProvider = provider
}

// SetPushedAuthorizationRequestStore installs the host's pushed authorization
// request store.
func (c *ServerConfig) SetPushedAuthorizationRequestStore(store storage.PushedAuthorizationRequestStore) {
	c.SetPushedAuthorizationRequestStoreProvider(func() storage.PushedAuthorizationRequestStore { return store })
}

// SetPushedAuthorizationDataProtectionProvider installs the data protection
// provider applied to pushed authorization payloads, and to nothing else.
// It must not be the default services/impl.DataProtectionProvider, which
// Freeze rejects.
func (c *ServerConfig) SetPushedAuthorizationDataProtectionProvider(provider dp.DataProtectionProvider) {
	c.pushedAuthorizationDataProtectionProvider = provider
}

// enablePushedAuthorization records that pushed authorization is enabled,
// which makes both of its seams required.
func (c *ServerConfig) enablePushedAuthorization() {
	c.pushedAuthorizationEnabled = true
}

// pushedAuthorizationRequired reports whether pushed authorization is
// enabled, which is the condition of both feature-required seams.
func (c *ServerConfig) pushedAuthorizationRequired() bool {
	return c != nil && c.pushedAuthorizationEnabled
}

// pushedAuthorizationRequestStoreForFeature returns the host's pushed
// authorization request store to the enabled feature. It fails while pushed
// authorization is disabled, when the host injected no store, and when the
// provider returned nil. The provider is called once, on the first call
// that gets past those checks; later calls return the same store.
func (c *ServerConfig) pushedAuthorizationRequestStoreForFeature() (storage.PushedAuthorizationRequestStore, error) {
	if !c.pushedAuthorizationRequired() {
		return nil, fmt.Errorf("store seam %q used although pushed authorization is not enabled", pushedAuthorizationRequestStoreSeamName)
	}
	if c.pushedAuthorizationRequestStoreProvider == nil {
		return nil, fmt.Errorf("store seam %q not injected by host", pushedAuthorizationRequestStoreSeamName)
	}
	c.pushedAuthorizationRequestStoreOnce.Do(func() {
		c.pushedAuthorizationRequestStore = c.pushedAuthorizationRequestStoreProvider()
	})
	if c.pushedAuthorizationRequestStore == nil {
		return nil, fmt.Errorf("store seam %q not injected by host: its provider returned nil", pushedAuthorizationRequestStoreSeamName)
	}
	return c.pushedAuthorizationRequestStore, nil
}

// pushedAuthorizationProtectorForFeature returns the protector of pushed
// authorization payloads, created from the host's provider with
// storage.PushedAuthorizationRequestPurpose. It fails while pushed
// authorization is disabled, when the host injected no provider, when the
// provider is the default implementation, and when it creates no protector.
func (c *ServerConfig) pushedAuthorizationProtectorForFeature() (dp.DataProtector, error) {
	if !c.pushedAuthorizationRequired() {
		return nil, fmt.Errorf("store seam %q used although pushed authorization is not enabled", pushedAuthorizationDataProtectionSeamName)
	}
	provider := c.pushedAuthorizationDataProtectionProvider
	if provider == nil {
		return nil, fmt.Errorf("store seam %q not injected by host", pushedAuthorizationDataProtectionSeamName)
	}
	if isDefaultDataProtectionProvider(provider) {
		return nil, fmt.Errorf("store seam %q injected with the default %T, which only encodes", pushedAuthorizationDataProtectionSeamName, provider)
	}
	protector := provider.Create(storage.PushedAuthorizationRequestPurpose)
	if protector == nil {
		return nil, fmt.Errorf("store seam %q: provider %T created no protector", pushedAuthorizationDataProtectionSeamName, provider)
	}
	return protector, nil
}

// isDefaultDataProtectionProvider reports whether provider is the default
// services/impl.DataProtectionProvider, including a nil pointer of that type.
// Only the pointer type implements dp.DataProtectionProvider, so it is the
// only form an injected value can take.
func isDefaultDataProtectionProvider(provider dp.DataProtectionProvider) bool {
	_, ok := provider.(*services_impl.DataProtectionProvider)
	return ok
}

// requirePushedAuthorizationDataProtectionSeam rejects the default data
// protection implementation on the pushed authorization seam, whether or not
// pushed authorization is enabled.
func (c *ServerConfig) requirePushedAuthorizationDataProtectionSeam() {
	if c.pushedAuthorizationDataProtectionProvider == nil {
		return
	}
	if isDefaultDataProtectionProvider(c.pushedAuthorizationDataProtectionProvider) {
		panic(fmt.Sprintf("store seam %q injected by host with the default %T, which only encodes; inject a provider that protects pushed authorization payloads", pushedAuthorizationDataProtectionSeamName, c.pushedAuthorizationDataProtectionProvider))
	}
}

// EnablePushedAuthorizationRequests enables pushed authorization requests
// (RFC 9126) with options. It is the only switch of the feature: the pushed
// authorization request endpoint and its mutual TLS alias are routed, the
// authorize endpoint resolves pushed request_uri values, and discovery
// advertises the endpoint, all only once it was called. Both pushed
// authorization seams become required. It panics after Freeze and for an
// option with a negative duration.
func (c *ServerConfig) EnablePushedAuthorizationRequests(options pushedauth.Options) {
	if c.frozen {
		panic("EnablePushedAuthorizationRequests must not be called after Freeze")
	}
	if err := options.Validate(); err != nil {
		panic(err.Error())
	}
	c.pushedAuthorizationOptions = options
	c.enablePushedAuthorization()
}

// PushedAuthorizationRequestsEnabled reports whether pushed authorization
// requests were enabled with EnablePushedAuthorizationRequests.
func (c *ServerConfig) PushedAuthorizationRequestsEnabled() bool {
	return c.pushedAuthorizationRequired()
}

// PushedAuthorizationRequestsOptions returns the effective options: the
// declared ones with every zero duration replaced by its default, and
// RequireForAllClients set while the high security profile is enabled. It
// returns the zero value while the feature is not enabled. The clock is
// returned as declared.
func (c *ServerConfig) PushedAuthorizationRequestsOptions() pushedauth.Options {
	if !c.PushedAuthorizationRequestsEnabled() {
		return pushedauth.Options{}
	}
	return c.effectivePushedAuthorizationOptions().WithDefaults()
}

// effectivePushedAuthorizationOptions returns the declared options with the
// tightening of the high security profile folded in, defaults not applied.
func (c *ServerConfig) effectivePushedAuthorizationOptions() pushedauth.Options {
	options := c.pushedAuthorizationOptions
	if c.HighSecurityProfileEnabled() {
		options.RequireForAllClients = true
	}
	return options
}

// pushedAuthorizationProtectorOnceForFeature returns the protector of the
// enabled feature, created on the first call and kept afterwards.
func (c *ServerConfig) pushedAuthorizationProtectorOnceForFeature() (dp.DataProtector, error) {
	if !c.pushedAuthorizationRequired() {
		return c.pushedAuthorizationProtectorForFeature()
	}
	c.pushedAuthorizationProtectorOnce.Do(func() {
		c.pushedAuthorizationProtector, c.pushedAuthorizationProtectorErr = c.pushedAuthorizationProtectorForFeature()
	})
	return c.pushedAuthorizationProtector, c.pushedAuthorizationProtectorErr
}

// pushedAuthorizationService builds the pushed authorization service of the
// enabled feature over the host's seams, which are materialized once, and
// clients, the client store of the resolving scope. A nil clock in the
// declared options is replaced by clock.
func (c *ServerConfig) pushedAuthorizationService(clients storage.ClientStore, clock pushedauth.Clock) (*pushedauth.Service, error) {
	store, err := c.pushedAuthorizationRequestStoreForFeature()
	if err != nil {
		return nil, err
	}
	protector, err := c.pushedAuthorizationProtectorOnceForFeature()
	if err != nil {
		return nil, err
	}
	options := c.effectivePushedAuthorizationOptions()
	if options.Clock == nil {
		options.Clock = clock
	}
	return pushedauth.NewService(store, protector, clients, options)
}
