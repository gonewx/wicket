// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"testing"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/storagetest"
)

// TestPersistedGrantStoreConformanceE2E wires the in-repo persisted grant
// store into the public conformance suite. Every case (MUST and MAY) must
// pass.
func TestPersistedGrantStoreConformanceE2E(t *testing.T) {
	storagetest.RunPersistedGrantStoreSuite(t, func() storage.PersistedGrantStore {
		return NewMemoryPersistedGrantStore()
	}, storagetest.WithMay(true))
}

func TestDeviceFlowStoreConformanceE2E(t *testing.T) {
	storagetest.RunDeviceFlowStoreSuite(t, func() storage.DeviceFlowStore {
		return NewMemoryDeviceFlowStore()
	}, storagetest.WithMay(true))
}

func TestBackchannelAuthenticationRequestStoreConformanceE2E(t *testing.T) {
	storagetest.RunBackchannelAuthenticationRequestStoreSuite(t, func() storage.BackchannelAuthenticationRequestStore {
		return NewMemoryBackchannelAuthenticationRequestStore()
	}, storagetest.WithMay(true))
}

func TestClientRegistrationStoreConformanceE2E(t *testing.T) {
	storagetest.RunClientRegistrationStoreSuite(t, func() storage.ClientRegistrationStore {
		return NewMemoryClientRegistrationStore()
	}, storagetest.WithMay(true))
}

func TestPushedAuthorizationRequestStoreConformanceE2E(t *testing.T) {
	storagetest.RunPushedAuthorizationRequestStoreSuite(t, func() storage.PushedAuthorizationRequestStore {
		return NewMemoryPushedAuthorizationRequestStore()
	}, storagetest.WithMay(true))
}
