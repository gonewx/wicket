// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/utils"
)

type Resources struct {
	OfflineAccess     bool
	identityResources map[*IdentityResource]*IdentityResource
	apiResources      map[*ApiResource]*ApiResource
	apiScopes         map[*ApiScope]*ApiScope
}

func WithResourcesOfflineAccess(offlineAccess bool) wicket.Option[Resources] {
	return func(r *Resources) {
		r.OfflineAccess = offlineAccess
	}
}

func WithResourcesIdentityResources(identityResources []*IdentityResource) wicket.Option[Resources] {
	return func(r *Resources) {
		for _, identityResource := range identityResources {
			r.identityResources[identityResource] = identityResource
		}
	}
}

func WithResourcesApiResources(apiResources []*ApiResource) wicket.Option[Resources] {
	return func(r *Resources) {
		for _, apiResource := range apiResources {
			r.apiResources[apiResource] = apiResource
		}
	}
}

func WithResourcesApiScopes(apiScopes []*ApiScope) wicket.Option[Resources] {
	return func(r *Resources) {
		for _, apiScope := range apiScopes {
			r.apiScopes[apiScope] = apiScope
		}
	}
}

func NewResources(opts ...wicket.Option[Resources]) *Resources {
	resources := &Resources{
		OfflineAccess:     false,
		identityResources: make(map[*IdentityResource]*IdentityResource, 0),
		apiResources:      make(map[*ApiResource]*ApiResource, 0),
		apiScopes:         make(map[*ApiScope]*ApiScope, 0),
	}

	for _, opt := range opts {
		opt(resources)
	}

	return resources
}

func (r *Resources) IdentityResources() []*IdentityResource {
	identityResources := make([]*IdentityResource, 0)
	for identityResource := range r.identityResources {
		identityResources = append(identityResources, identityResource)
	}

	return identityResources
}

func (r *Resources) ApiResources() []*ApiResource {
	apiResources := make([]*ApiResource, 0)
	for apiResource := range r.apiResources {
		apiResources = append(apiResources, apiResource)
	}

	return apiResources
}

func (r *Resources) ApiScopes() []*ApiScope {
	apiScopes := make([]*ApiScope, 0)
	for apiScope := range r.apiScopes {
		apiScopes = append(apiScopes, apiScope)
	}

	return apiScopes
}

// Converts to scope names.
func (r *Resources) ToScopeNames() []string {
	names := utils.Select(r.IdentityResources(), func(x *IdentityResource) string { return x.Name })
	names = append(names, utils.Select(r.ApiScopes(), func(x *ApiScope) string { return x.Name })...)
	if r.OfflineAccess {
		names = append(names, wicket.StandardScopesOfflineAccess)
	}

	return names
}

// Finds the IdentityResource that matches the scope.
func (r *Resources) FindIdentityResourcesByScope(name string) *IdentityResource {
	return utils.FirstOrDefaultPred(r.IdentityResources(), func(x *IdentityResource) bool {
		return x.Name == name
	})
}

// Finds the API resources that contain the scope.
func (r *Resources) FindApiResourcesByScope(name string) []*ApiResource {
	apiResources := make([]*ApiResource, 0)
	for apiResource := range r.apiResources {
		if len(apiResource.Scopes) > 0 && utils.Contains(apiResource.Scopes, name) {
			apiResources = append(apiResources, apiResource)
		}
	}

	return apiResources
}

// Finds the API scope.
func (r *Resources) FindApiScope(name string) *ApiScope {
	return utils.FirstOrDefaultPred(r.ApiScopes(), func(x *ApiScope) bool {
		return x.Name == name
	})
}

func (r *Resources) FilterEnabled() *Resources {
	if r == nil {
		return NewResources()
	}

	return NewResources(
		WithResourcesIdentityResources(
			utils.Where(r.IdentityResources(), func(x *IdentityResource) bool { return x.Enabled }),
		),
		WithResourcesApiResources(
			utils.Where(r.ApiResources(), func(x *ApiResource) bool { return x.Enabled }),
		),
		WithResourcesApiScopes(
			utils.Where(r.ApiScopes(), func(x *ApiScope) bool { return x.Enabled }),
		),
		WithResourcesOfflineAccess(r.OfflineAccess),
	)
}

// AddApiResource
// return true if the ApiResource is added
// return false if the ApiResource is already present;
func (r *Resources) AddApiResource(api *ApiResource) bool {
	if _, ok := r.apiResources[api]; ok {
		return false
	}

	r.apiResources[api] = api
	return true
}

// AddIdentityResource
// return true if the IdentityResource is added
// return false if the IdentityResource is already present;
func (r *Resources) AddIdentityResource(identity *IdentityResource) bool {
	if _, ok := r.identityResources[identity]; ok {
		return false
	}

	r.identityResources[identity] = identity
	return true
}

// AddApiScope
// return true if the ApiScope is added
// return false if the ApiScope is already present;
func (r *Resources) AddApiScope(scope *ApiScope) bool {
	if _, ok := r.apiScopes[scope]; ok {
		return false
	}

	r.apiScopes[scope] = scope
	return true
}

// RemoveApiResource
// return true if the ApiResource is removed
// return false if the ApiResource is not present;
func (r *Resources) RemoveApiResource(api *ApiResource) bool {
	if _, ok := r.apiResources[api]; !ok {
		return false
	}

	delete(r.apiResources, api)
	return true
}

// RemoveIdentityResource
// return true if the IdentityResource is removed
// return false if the IdentityResource is not present;
func (r *Resources) RemoveIdentityResource(identity *IdentityResource) bool {
	if _, ok := r.identityResources[identity]; !ok {
		return false
	}

	delete(r.identityResources, identity)
	return true
}

// RemoveApiScope
// return true if the ApiScope is removed
// return false if the ApiScope is not present;
func (r *Resources) RemoveApiScope(scope *ApiScope) bool {
	if _, ok := r.apiScopes[scope]; !ok {
		return false
	}

	delete(r.apiScopes, scope)
	return true
}

// RemoveAllIdentityResource
func (r *Resources) RemoveAllIdentityResource() {
	r.identityResources = nil
}

// RemoveAllApiResource
func (r *Resources) RemoveAllApiResource() {
	r.apiResources = nil
}

// RemoveAllApiScope
func (r *Resources) RemoveAllApiScope() {
	r.apiScopes = nil
}
