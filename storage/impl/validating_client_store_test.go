// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	"github.com/stretchr/testify/require"
)

type missingClientStore struct{}

func (missingClientStore) FindClientById(ctx context.Context, id string) (*storage_models.Client, error) {
	return nil, nil
}

type trackingClientConfigurationValidator struct {
	called bool
}

func (v *trackingClientConfigurationValidator) Validate(ctx *validators_contexts.ClientConfigurationValidationContext) {
	v.called = true
}

func TestValidatingClientStoreReturnsNotFoundWhenClientMissing(t *testing.T) {
	validator := &trackingClientConfigurationValidator{}
	store := NewValidatingClientStore(
		missingClientStore{},
		validator,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	client, err := store.FindClientById(context.Background(), "missing")

	require.ErrorIs(t, err, storage.ErrNotFound)
	require.Nil(t, client)
	require.False(t, validator.called, "missing clients should not run configuration validation")
}

type fixedClientStore struct {
	client *storage_models.Client
	err    error
}

func (s fixedClientStore) FindClientById(ctx context.Context, id string) (*storage_models.Client, error) {
	return s.client, s.err
}

type verdictClientConfigurationValidator struct {
	valid   bool
	message string
}

func (v verdictClientConfigurationValidator) Validate(ctx *validators_contexts.ClientConfigurationValidationContext) {
	if !v.valid {
		ctx.SetError(v.message)
	}
}

func TestValidatingClientStoreSentinels(t *testing.T) {
	t.Parallel()

	infrastructure := errors.New("database unavailable")
	tests := map[string]struct {
		inner      fixedClientStore
		validator  verdictClientConfigurationValidator
		wantClient bool
		wantIs     error
		notIs      []error
		wantText   []string
	}{
		"inner reports not found": {
			inner:  fixedClientStore{err: storage.ErrNotFound},
			wantIs: storage.ErrNotFound,
			notIs:  []error{storage.ErrInvalidClientConfiguration},
		},
		"inner returns nil client": {
			inner:  fixedClientStore{},
			wantIs: storage.ErrNotFound,
			notIs:  []error{storage.ErrInvalidClientConfiguration},
		},
		"inner infrastructure error passes through": {
			inner:  fixedClientStore{err: infrastructure},
			wantIs: infrastructure,
			notIs:  []error{storage.ErrNotFound, storage.ErrInvalidClientConfiguration},
		},
		"validation failure": {
			inner:     fixedClientStore{client: &storage_models.Client{ClientId: "broken"}},
			validator: verdictClientConfigurationValidator{message: "feature not enabled"},
			wantIs:    storage.ErrInvalidClientConfiguration,
			notIs:     []error{storage.ErrNotFound},
			wantText:  []string{"broken", "feature not enabled"},
		},
		"validation success": {
			inner:      fixedClientStore{client: &storage_models.Client{ClientId: "ok"}},
			validator:  verdictClientConfigurationValidator{valid: true},
			wantClient: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := NewValidatingClientStore(tc.inner, tc.validator, slog.New(slog.NewTextHandler(io.Discard, nil)))
			client, err := store.FindClientById(context.Background(), "id")
			if tc.wantClient {
				require.NoError(t, err)
				require.NotNil(t, client)
				return
			}
			require.Nil(t, client)
			require.ErrorIs(t, err, tc.wantIs)
			for _, other := range tc.notIs {
				require.False(t, errors.Is(err, other), "error %v must not match %v", err, other)
			}
			for _, text := range tc.wantText {
				require.True(t, strings.Contains(err.Error(), text), "error %q must mention %q", err.Error(), text)
			}
		})
	}
}
