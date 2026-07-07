// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package extensions

import (
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

func FindEnabledClientById(store storage.ClientStore, id string) (*storage_models.Client, error) {
	client, err := store.FindClientById(id)
	if err != nil || client == nil || !client.Enabled {
		return nil, err
	}
	return client, nil
}

func FindEnabledIdentityResourcesByScope(store storage.ResourceStore, scopes []string) ([]*storage_models.IdentityResource, error) {
	resources, err := store.FindIdentityResourcesByScope(scopes)
	if err != nil {
		return nil, err
	}
	return utils.Where(resources, func(resource *storage_models.IdentityResource) bool {
		return resource != nil && resource.Enabled
	}), nil
}
