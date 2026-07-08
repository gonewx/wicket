// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type ResourceValidator struct {
	store  storage.ResourceStore
	parser validators.ScopeParser
}

func NewResourceValidator(store storage.ResourceStore, parser validators.ScopeParser, logger *slog.Logger) *ResourceValidator {
	return &ResourceValidator{store: store, parser: parser}
}

func (v *ResourceValidator) ValidateRequestedResources(request *validators_models.ResourceValidationRequest) (*validators_models.ResourceValidationResult, error) {
	result := validators_models.NewResourceValidationResult()
	if request == nil {
		return result, nil
	}

	requestedScopes := request.Scopes
	if v.parser != nil {
		parsed := v.parser.ParseScopeValues(requestedScopes)
		if parsed != nil {
			result.ParsedScopes = parsed.ParsedScopes
			for _, err := range parsed.Errors {
				result.InvalidScopes = append(result.InvalidScopes, err.RawValue)
			}
		}
	} else {
		for _, scope := range requestedScopes {
			result.ParsedScopes = append(result.ParsedScopes, &validators_models.ParsedScopeValue{
				RawValue:   scope,
				ParsedName: scope,
			})
		}
	}

	resourceGaps := utils.Distinct(request.ResourceGaps)
	validResourceGaps := make([]string, 0, len(resourceGaps))
	for _, resourceGap := range resourceGaps {
		if !utils.IsValidResourceGapFormat(resourceGap) {
			result.InvalidResourceGaps = appendResourceGapDistinct(result.InvalidResourceGaps, resourceGap)
			continue
		}
		validResourceGaps = append(validResourceGaps, resourceGap)
	}

	scopeNames := parsedScopeNames(result.ParsedScopes)
	resources := storage_models.NewResources()
	if v.store != nil {
		found, err := v.store.FindResourcesByScope(scopeNames)
		if err != nil {
			return nil, err
		}
		if found != nil {
			resources = found
		}
	}

	identityResources := enabledIdentityResources(resources.IdentityResources())
	apiScopes := enabledApiScopes(resources.ApiScopes())
	apiResources := enabledApiResources(resources.ApiResources())
	apiScopeByName := mapApiScopes(apiScopes)
	identityByName := mapIdentityResources(identityResources)

	validScopeNames := make([]string, 0, len(result.ParsedScopes))
	for _, parsedScope := range result.ParsedScopes {
		if parsedScope == nil {
			continue
		}
		scopeName := parsedScope.ParsedName
		if scopeName == "" {
			scopeName = parsedScope.RawValue
		}
		if !clientAllowsScope(request.Client, scopeName) {
			result.InvalidScopes = appendDistinct(result.InvalidScopes, parsedScope.RawValue)
			continue
		}
		if scopeName == gois.StandardScopesOfflineAccess {
			if request.Client == nil || request.Client.AllowOfflineAccess {
				validScopeNames = appendDistinct(validScopeNames, scopeName)
				continue
			}
			result.InvalidScopes = appendDistinct(result.InvalidScopes, parsedScope.RawValue)
			continue
		}
		if _, ok := identityByName[scopeName]; ok {
			validScopeNames = appendDistinct(validScopeNames, scopeName)
			continue
		}
		if _, ok := apiScopeByName[scopeName]; ok {
			validScopeNames = appendDistinct(validScopeNames, scopeName)
			continue
		}
		result.InvalidScopes = appendDistinct(result.InvalidScopes, parsedScope.RawValue)
	}

	requestedApiResources := map[string]*storage_models.ApiResource{}
	if len(validResourceGaps) > 0 && v.store != nil {
		found, err := v.store.FindApiResourcesByName(validResourceGaps)
		if err != nil {
			return nil, err
		}
		for _, resource := range enabledApiResources(found) {
			requestedApiResources[resource.Name] = resource
		}
	}
	for _, resourceGap := range validResourceGaps {
		if _, ok := requestedApiResources[resourceGap]; !ok {
			result.InvalidResourceGaps = appendResourceGapDistinct(result.InvalidResourceGaps, resourceGap)
		}
	}

	selectedApiResources := apiResources
	if len(resourceGaps) > 0 {
		selectedApiResources = make([]*storage_models.ApiResource, 0)
		for _, resourceGap := range validResourceGaps {
			resource := requestedApiResources[resourceGap]
			if resource == nil {
				continue
			}
			if !apiResourceHasScope(resource, validScopeNames) {
				if len(result.InvalidScopes) == 0 {
					result.InvalidResourceGaps = appendResourceGapDistinct(result.InvalidResourceGaps, resourceGap)
				}
				continue
			}
			selectedApiResources = appendApiResourceDistinct(selectedApiResources, resource)
		}
		if request.IncludeNonIsolatedApiResources {
			for _, resource := range apiResources {
				if resource != nil && !resource.RequireResourceGap && apiResourceHasScope(resource, validScopeNames) {
					selectedApiResources = appendApiResourceDistinct(selectedApiResources, resource)
				}
			}
		}
	}

	apiScopeNamesToKeep := map[string]struct{}{}
	for _, resource := range selectedApiResources {
		for _, scope := range resource.Scopes {
			if contains(validScopeNames, scope) {
				apiScopeNamesToKeep[scope] = struct{}{}
			}
		}
	}
	apiScopesToKeep := make([]*storage_models.ApiScope, 0)
	for _, scope := range apiScopes {
		if _, ok := apiScopeNamesToKeep[scope.Name]; ok {
			apiScopesToKeep = append(apiScopesToKeep, scope)
		}
	}
	identityResourcesToKeep := make([]*storage_models.IdentityResource, 0)
	for _, resource := range identityResources {
		if contains(validScopeNames, resource.Name) {
			identityResourcesToKeep = append(identityResourcesToKeep, resource)
		}
	}

	result.Resources = storage_models.NewResources(
		storage_models.WithResourcesOfflineAccess(contains(validScopeNames, gois.StandardScopesOfflineAccess)),
		storage_models.WithResourcesIdentityResources(identityResourcesToKeep),
		storage_models.WithResourcesApiResources(selectedApiResources),
		storage_models.WithResourcesApiScopes(apiScopesToKeep),
	)

	return result, nil
}

func parsedScopeNames(scopes []*validators_models.ParsedScopeValue) []string {
	names := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == nil {
			continue
		}
		name := scope.ParsedName
		if name == "" {
			name = scope.RawValue
		}
		names = append(names, name)
	}
	return names
}

func clientAllowsScope(client *storage_models.Client, scope string) bool {
	if client == nil {
		return true
	}
	if scope == gois.StandardScopesOfflineAccess && client.AllowOfflineAccess {
		return true
	}
	return utils.Contains(client.AllowedScopes, scope)
}

func enabledIdentityResources(resources []*storage_models.IdentityResource) []*storage_models.IdentityResource {
	return utils.Where(resources, func(resource *storage_models.IdentityResource) bool {
		return resource != nil && resource.Enabled
	})
}

func enabledApiScopes(scopes []*storage_models.ApiScope) []*storage_models.ApiScope {
	return utils.Where(scopes, func(scope *storage_models.ApiScope) bool {
		return scope != nil && scope.Enabled
	})
}

func enabledApiResources(resources []*storage_models.ApiResource) []*storage_models.ApiResource {
	return utils.Where(resources, func(resource *storage_models.ApiResource) bool {
		return resource != nil && resource.Enabled
	})
}

func mapApiScopes(scopes []*storage_models.ApiScope) map[string]*storage_models.ApiScope {
	out := make(map[string]*storage_models.ApiScope, len(scopes))
	for _, scope := range scopes {
		out[scope.Name] = scope
	}
	return out
}

func mapIdentityResources(resources []*storage_models.IdentityResource) map[string]*storage_models.IdentityResource {
	out := make(map[string]*storage_models.IdentityResource, len(resources))
	for _, resource := range resources {
		out[resource.Name] = resource
	}
	return out
}

func apiResourceHasScope(resource *storage_models.ApiResource, scopes []string) bool {
	if resource == nil {
		return false
	}
	for _, scope := range resource.Scopes {
		if contains(scopes, scope) {
			return true
		}
	}
	return false
}

func appendApiResourceDistinct(resources []*storage_models.ApiResource, resource *storage_models.ApiResource) []*storage_models.ApiResource {
	if resource == nil {
		return resources
	}
	for _, existing := range resources {
		if existing == resource || existing.Name == resource.Name {
			return resources
		}
	}
	return append(resources, resource)
}

func appendDistinct(values []string, value string) []string {
	if strings.TrimSpace(value) == "" {
		return values
	}
	if contains(values, value) {
		return values
	}
	return append(values, value)
}

func appendResourceGapDistinct(values []string, value string) []string {
	if contains(values, value) {
		return values
	}
	return append(values, value)
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
