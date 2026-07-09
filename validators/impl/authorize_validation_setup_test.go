// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"

	config_options "github.com/gonewx/wicket/config/options"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage/memory"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// createAuthorizeRequestValidator wires an AuthorizeRequestValidator against
// the shared in-memory client and resource fixtures so protocol-level table
// tests can validate raw authorize parameters without a composition root.
func createAuthorizeRequestValidator() (*AuthorizeRequestValidator, error) {
	options := config_options.NewWicketOptions()

	clientStore, err := memory.NewMemoryClientStore(validators_mock.TestClients{}.Get())
	if err != nil {
		return nil, err
	}

	scopes := &validators_mock.TestScopes{}
	resourceStore, err := memory.NewMemoryResourcesStore(scopes.GetIdentity(), scopes.GetApis(), scopes.GetScopes())
	if err != nil {
		return nil, err
	}

	return NewAuthorizeRequestValidator(
		slog.Default(),
		options,
		services_impl.NewIssuerNameService(options),
		clientStore,
		nil,
		nil,
		NewStrictRedirectUriValidator(),
		NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
		nil,
		NewCustomAuthorizeRequestValidator(),
	), nil
}
