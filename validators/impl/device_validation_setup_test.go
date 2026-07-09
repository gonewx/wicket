// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"
	"time"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/memory"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// deviceCodeTestNow is the fixed reference instant injected into device-flow
// tests so lifetime arithmetic never depends on the real wall clock.
var deviceCodeTestNow = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

type deviceCodeTestClock struct{ now time.Time }

func (c deviceCodeTestClock) Now() time.Time { return c.now }

// createClientStore builds an in-memory client store over the shared client
// fixtures.
func createClientStore() (storage.ClientStore, error) {
	return memory.NewMemoryClientStore(validators_mock.TestClients{}.Get())
}

// createDeviceCodeService wires a device flow code service over an in-memory
// grant store.
func createDeviceCodeService() *services_impl.DeviceFlowCodeService {
	return services_impl.NewDeviceFlowCodeService(memory.NewMemoryDeviceFlowStore(), services_impl.NewHandleGenerationService())
}

// createDeviceCodeValidator wires a DeviceCodeValidator, substituting
// permissive defaults for any seam the caller leaves nil.
func createDeviceCodeValidator(
	devices services.DeviceFlowCodeService,
	profile services.ProfileService,
	throttlingService services.DeviceFlowThrottlingService,
	systemClock services.SystemClock,
) *DeviceCodeValidator {
	if profile == nil {
		profile = validators_mock.NewTestProfileService(true)
	}
	if throttlingService == nil {
		throttlingService = validators_mock.NewTestDeviceFlowThrottlingService(false)
	}
	if systemClock == nil {
		systemClock = deviceCodeTestClock{now: deviceCodeTestNow}
	}
	return NewDeviceCodeValidator(devices, profile, throttlingService, systemClock, slog.Default())
}

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
