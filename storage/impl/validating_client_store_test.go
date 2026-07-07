// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"io"
	"log/slog"
	"testing"

	storage_models "github.com/gonewx/wicket/storage/models"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	"github.com/stretchr/testify/require"
)

type missingClientStore struct{}

func (missingClientStore) FindClientById(id string) (*storage_models.Client, error) {
	return nil, nil
}

type trackingClientConfigurationValidator struct {
	called bool
}

func (v *trackingClientConfigurationValidator) Validate(ctx *validators_contexts.ClientConfigurationValidationContext) {
	v.called = true
}

func TestValidatingClientStoreReturnsNilWhenClientMissing(t *testing.T) {
	validator := &trackingClientConfigurationValidator{}
	store := NewValidatingClientStore(
		missingClientStore{},
		validator,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	client, err := store.FindClientById("missing")

	require.NoError(t, err)
	require.Nil(t, client)
	require.False(t, validator.called, "missing clients should not run configuration validation")
}
