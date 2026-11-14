// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"fmt"
	"log/slog"

	services_memory "github.com/gonewx/wicket/services/memory"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

// clientStoreSource returns the client store every read path is built on: the
// host-injected store when there is one, otherwise an in-memory store over
// the static client list. The caller wraps it in the validating decorator.
func clientStoreSource(cfg *ServerConfig) storage.ClientStore {
	if injected := cfg.ClientStore(); injected != nil {
		return injected
	}
	return staticClientStore(cfg)
}

func staticClientStore(cfg *ServerConfig) *storage_memory.MemoryClientStore {
	store, err := storage_memory.NewMemoryClientStore(cfg.Clients())
	if err != nil {
		panic(fmt.Errorf("construct MemoryClientStore: %w", err))
	}
	return store
}

// newCorsPolicyService builds the CORS policy over the same client data the
// client store serves. With an injected store, a client matching the origin
// counts only when it is enabled and its configuration passes validation; the
// static client list keeps its plain origin match.
func newCorsPolicyService(cfg *ServerConfig, validator validators.ClientConfigurationValidator, logger *slog.Logger) *services_memory.MemoryCorsPolicyService {
	injected := cfg.ClientStore()
	if injected == nil {
		return services_memory.NewMemoryCorsPolicyService(logger, staticClientStore(cfg), nil)
	}
	lookup, ok := injected.(storage.ClientOriginLookup)
	if !ok {
		// Freeze rejects such a store; this guards an unfrozen configuration.
		panic(fmt.Sprintf("client store injected by host (%T) does not implement storage.ClientOriginLookup", injected))
	}
	return services_memory.NewMemoryCorsPolicyService(logger, lookup, func(_ context.Context, client *storage_models.Client) bool {
		if !client.Enabled {
			return false
		}
		validation := validators_contexts.NewClientConfigurationValidationContext(client)
		validator.Validate(validation)
		return validation.IsValid
	})
}
