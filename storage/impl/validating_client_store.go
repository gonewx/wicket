// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

// ValidatingClientStore Client store decorator for running runtime configuration validation checks
type ValidatingClientStore[T storage.ClientStore] struct {
	inner     storage.ClientStore
	validator validators.ClientConfigurationValidator
	logger    *slog.Logger
}

func NewValidatingClientStore[T storage.ClientStore](
	inner T,
	validator validators.ClientConfigurationValidator,
	logger *slog.Logger,
) *ValidatingClientStore[T] {
	return &ValidatingClientStore[T]{
		inner:     inner,
		validator: validator,
		logger:    logger,
	}
}

// FindClientById Finds a client by id (and runs the validation logic)
func (s *ValidatingClientStore[T]) FindClientById(ctx context.Context, id string) (*storage_models.Client, error) {
	client, err := s.inner.FindClientById(ctx, id)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, storage.ErrNotFound
	}

	if s.logger.Enabled(ctx, slog.LevelDebug) {
		s.logger.Debug("Calling into client configuration validator", slog.String("validatorType", fmt.Sprintf("%T", s.validator)))
	}

	validationCtx := validators_contexts.NewClientConfigurationValidationContext(client)
	s.validator.Validate(validationCtx)

	if validationCtx.IsValid {
		s.logger.Debug("client configuration validation for client {clientId} succeeded.", slog.String("clientId", client.ClientId))
		return client, nil
	}

	s.logger.Error("Invalid client configuration for client.", slog.String("clientId", client.ClientId), slog.String("errorMessage", validationCtx.ErrorMessage))

	return nil, fmt.Errorf("%w: client %q: %s", storage.ErrInvalidClientConfiguration, client.ClientId, validationCtx.ErrorMessage)
}
