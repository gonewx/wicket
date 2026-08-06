// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"testing"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/storagetest"
)

// TestAuthorizationCodeStoreConformanceE2E wires the in-repo authorization
// code store into the public conformance suite. Every case (MUST and MAY)
// must pass.
func TestAuthorizationCodeStoreConformanceE2E(t *testing.T) {
	storagetest.RunAuthorizationCodeStoreSuite(t, func() storage.AuthorizationCodeStore {
		return NewAuthorizationCodeStore()
	}, storagetest.WithMay(true))
}

func TestRefreshTokenStoreConformanceE2E(t *testing.T) {
	storagetest.RunRefreshTokenStoreSuite(t, func() storage.RefreshTokenStore {
		return NewRefreshTokenStore()
	}, storagetest.WithMay(true))
}

func TestReferenceTokenStoreConformanceE2E(t *testing.T) {
	storagetest.RunReferenceTokenStoreSuite(t, func() storage.ReferenceTokenStore {
		return NewReferenceTokenStore()
	}, storagetest.WithMay(true))
}

func TestUserConsentStoreConformanceE2E(t *testing.T) {
	storagetest.RunUserConsentStoreSuite(t, func() storage.UserConsentStore {
		return NewUserConsentStore()
	}, storagetest.WithMay(true))
}
