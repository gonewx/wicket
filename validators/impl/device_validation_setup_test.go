// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/storage/memory"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// createDeviceAuthorizationRequestValidator wires a
// DeviceAuthorizationRequestValidator against the shared in-memory resource
// fixtures so device-flow table tests can validate raw request parameters
// without a composition root.
func createDeviceAuthorizationRequestValidator() (*DeviceAuthorizationRequestValidator, error) {
	options := config_options.NewWicketOptions()

	scopes := &validators_mock.TestScopes{}
	resourceStore, err := memory.NewMemoryResourcesStore(scopes.GetIdentity(), scopes.GetApis(), scopes.GetScopes())
	if err != nil {
		return nil, err
	}

	return NewDeviceAuthorizationRequestValidator(
		options,
		NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
		slog.Default(),
	), nil
}
