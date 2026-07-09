// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"time"

	config_options "github.com/gonewx/wicket/config/options"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	test_common "github.com/gonewx/wicket/test/common"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// tokenTestNow is the fixed reference instant injected into token validation
// tests so lifetime arithmetic never depends on the real wall clock.
var tokenTestNow = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// createReferenceTokenStore builds an empty in-memory reference token store.
func createReferenceTokenStore() *storage_impl.ReferenceTokenStore {
	return storage_impl.NewReferenceTokenStore()
}

type tokenValidatorSetup struct {
	referenceTokenStore storage.ReferenceTokenStore
}

type tokenValidatorOption func(*tokenValidatorSetup)

// withTokenValidatorStore lets a test share its reference token store with
// the validator under construction.
func withTokenValidatorStore(store storage.ReferenceTokenStore) tokenValidatorOption {
	return func(s *tokenValidatorSetup) {
		s.referenceTokenStore = store
	}
}

// createTokenValidator wires a TokenValidator over the shared in-memory
// client fixtures with permissive defaults for every seam a caller does not
// override.
func createTokenValidator(opts ...tokenValidatorOption) *TokenValidator {
	setup := &tokenValidatorSetup{}
	for _, opt := range opts {
		opt(setup)
	}
	if setup.referenceTokenStore == nil {
		setup.referenceTokenStore = createReferenceTokenStore()
	}

	clients, err := createClientStore()
	if err != nil {
		panic(err)
	}

	options := config_options.NewWicketOptions()
	return NewTokenValidator(
		test_common.NewTestLogger(),
		options,
		services_impl.NewIssuerNameService(options),
		setup.referenceTokenStore,
		NewCustomTokenValidator(),
		clients,
		validators_mock.NewTestProfileService(true),
		nil,
		nil,
		fixedTestClock{now: tokenTestNow},
	)
}
