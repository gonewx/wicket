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

func FindEnabledIdentityResourcesByScope(ctx context.Context, store storage.ResourceStore, scopes []string) ([]*storage_models.IdentityResource, error) {
	resources, err := store.FindIdentityResourcesByScope(ctx, scopes)
	if err != nil {
		return nil, err
	}
	return utils.Where(resources, func(resource *storage_models.IdentityResource) bool {
		return resource != nil && resource.Enabled
	}), nil
}
