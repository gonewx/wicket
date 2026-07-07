// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"fmt"

	"github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

type MemoryClientStore struct {
	clients map[string]*models.Client
}

func NewMemoryClientStore(clients []*models.Client) (*MemoryClientStore, error) {
	store := &MemoryClientStore{clients: map[string]*models.Client{}}
	for _, client := range clients {
		if client == nil {
			continue
		}
		if client.ClientId == "" {
			return nil, fmt.Errorf("client id is required")
		}
		if _, exists := store.clients[client.ClientId]; exists {
			return nil, fmt.Errorf("duplicate client id %q", client.ClientId)
		}
		store.clients[client.ClientId] = client
	}
	return store, nil
}

func (s *MemoryClientStore) FindClientById(id string) (*models.Client, error) {
	return s.clients[id], nil
}

type MemoryResourcesStore struct {
	identityResources []*models.IdentityResource
	apiResources      []*models.ApiResource
	apiScopes         []*models.ApiScope
}

func NewMemoryResourcesStore(identityResources []*models.IdentityResource, apiResources []*models.ApiResource, apiScopes []*models.ApiScope) (*MemoryResourcesStore, error) {
	return &MemoryResourcesStore{
		identityResources: identityResources,
		apiResources:      apiResources,
		apiScopes:         apiScopes,
	}, nil
}

func (s *MemoryResourcesStore) GetAllEnabledResources() (*models.Resources, error) {
	return models.NewResources(
		models.WithResourcesIdentityResources(utils.Where(s.identityResources, func(x *models.IdentityResource) bool { return x.Enabled })),
		models.WithResourcesApiResources(utils.Where(s.apiResources, func(x *models.ApiResource) bool { return x.Enabled })),
		models.WithResourcesApiScopes(utils.Where(s.apiScopes, func(x *models.ApiScope) bool { return x.Enabled })),
	), nil
}

func (s *MemoryResourcesStore) FindResourcesByScope(scopes []string) (*models.Resources, error) {
	identity, _ := s.FindIdentityResourcesByScope(scopes)
	apiScopes, _ := s.FindApiScopesByName(scopes)
	apiScopeNames := utils.Select(apiScopes, func(scope *models.ApiScope) string { return scope.Name })
	apiResources := utils.Where(s.apiResources, func(resource *models.ApiResource) bool {
		return resource != nil && utils.AnyPred(resource.Scopes, func(scope string) bool {
			return utils.Contains(apiScopeNames, scope)
		})
	})
	return models.NewResources(
		models.WithResourcesIdentityResources(identity),
		models.WithResourcesApiResources(apiResources),
		models.WithResourcesApiScopes(apiScopes),
	), nil
}

func (s *MemoryResourcesStore) FindApiResourcesByName(names []string) ([]*models.ApiResource, error) {
	return utils.Where(s.apiResources, func(resource *models.ApiResource) bool {
		return resource != nil && utils.Contains(names, resource.Name)
	}), nil
}

func (s *MemoryResourcesStore) FindApiScopesByName(names []string) ([]*models.ApiScope, error) {
	return utils.Where(s.apiScopes, func(scope *models.ApiScope) bool {
		return scope != nil && utils.Contains(names, scope.Name)
	}), nil
}

func (s *MemoryResourcesStore) FindIdentityResourcesByScope(scopes []string) ([]*models.IdentityResource, error) {
	return utils.Where(s.identityResources, func(resource *models.IdentityResource) bool {
		return resource != nil && utils.Contains(scopes, resource.Name)
	}), nil
}
