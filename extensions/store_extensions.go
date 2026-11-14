// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package extensions

import (
	"context"
	"errors"

	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

// FindEnabledClientById returns the enabled client, or storage.ErrNotFound when
// no such client exists (including a disabled one), so callers can distinguish
// a miss from an infrastructure failure.
func FindEnabledClientById(ctx context.Context, store storage.ClientStore, id string) (*storage_models.Client, error) {
	client, err := store.FindClientById(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	if client == nil || !client.Enabled {
		return nil, storage.ErrNotFound
	}
	return client, nil
}

// IsClientRejected reports whether a client load error means the client cannot
// be used — absent, disabled, or with an invalid configuration — as opposed to
// an infrastructure failure. Existence gates answer a rejected client with the
// protocol's invalid-credential result and any other error with a server
// error.
func IsClientRejected(err error) bool {
	return errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrInvalidClientConfiguration)
}

func FindEnabledIdentityResourcesByScope(ctx context.Context, store storage.ResourceStore, scopes []string) ([]*storage_models.IdentityResource, error) {
	resources, err := store.FindIdentityResourcesByScope(ctx, scopes)
	if err != nil {
		return nil, err
	}
	return utils.Where(resources, func(resource *storage_models.IdentityResource) bool {
		return resource != nil && resource.Enabled
	}), nil
}
