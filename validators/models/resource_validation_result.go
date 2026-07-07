// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"strings"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

type ResourceValidationResult struct {
	// The resources of the result.
	Resources           *storage_models.Resources
	ParsedScopes        []*ParsedScopeValue
	InvalidResourceGaps []string
	InvalidScopes       []string
}

func NewResourceValidationResult() *ResourceValidationResult {
	return &ResourceValidationResult{
		Resources: storage_models.NewResources(),
	}
}

func NewResourceValidationResultWithResources(resources *storage_models.Resources) *ResourceValidationResult {
	return &ResourceValidationResult{
		Resources: resources,
		ParsedScopes: utils.Select(resources.ToScopeNames(),
			func(x string) *ParsedScopeValue { return &ParsedScopeValue{RawValue: x, ParsedName: x} }),
	}
}

// Indicates if the result was successful.
func (r *ResourceValidationResult) Succeeded() bool {
	return utils.Any(r.ParsedScopes) && !utils.Any(r.InvalidScopes) && !utils.Any(r.InvalidResourceGaps)
}

func (r *ResourceValidationResult) RawScopeValues() []string {
	return utils.Select(r.ParsedScopes, func(x *ParsedScopeValue) string {
		return x.RawValue
	})
}

// Returns new result filted by the scope values.
func (r *ResourceValidationResult) Filter(scopeValues []string) *ResourceValidationResult {
	result := &ResourceValidationResult{}

	offline := utils.Contains(scopeValues, gois.StandardScopesOfflineAccess)

	parsedScopesToKeep := utils.Where(r.ParsedScopes, func(x *ParsedScopeValue) bool {
		return utils.Contains(scopeValues, x.RawValue)
	})
	parsedScopeNamesToKeep := utils.Select(parsedScopesToKeep, func(x *ParsedScopeValue) string {
		return x.ParsedName
	})

	identityToKeep := utils.Where(r.Resources.IdentityResources(), func(x *storage_models.IdentityResource) bool {
		return utils.Contains(parsedScopeNamesToKeep, x.Name)
	})
	apiScopesToKeep := utils.Where(r.Resources.ApiScopes(), func(x *storage_models.ApiScope) bool {
		return utils.Contains(parsedScopeNamesToKeep, x.Name)
	})

	apiScopesNamesToKeep := utils.Select(apiScopesToKeep, func(x *storage_models.ApiScope) string {
		return x.Name
	})
	apiResourcesToKeep := utils.Where(r.Resources.ApiResources(), func(x *storage_models.ApiResource) bool {
		return utils.AnyPred(x.Scopes, func(y string) bool {
			return utils.Contains(apiScopesNamesToKeep, y)
		})
	})

	resources := storage_models.NewResources(
		storage_models.WithResourcesOfflineAccess(offline),
		storage_models.WithResourcesIdentityResources(identityToKeep),
		storage_models.WithResourcesApiResources(apiResourcesToKeep),
		storage_models.WithResourcesApiScopes(apiScopesToKeep),
	)

	result.Resources = resources
	result.ParsedScopes = parsedScopesToKeep

	return result
}

// Filters the result by the resource gap for issuing access tokens.
func (r *ResourceValidationResult) FilterByResourceGap(resourceIndicator string) *ResourceValidationResult {
	// filter ApiResources to only the ones allowed by the resource gap requested
	var apiResourcesToKeep []*storage_models.ApiResource
	if strings.TrimSpace(resourceIndicator) == "" {
		apiResourcesToKeep = utils.Where(r.Resources.ApiResources(), func(x *storage_models.ApiResource) bool {
			return !x.RequireResourceGap
		})
	} else {
		apiResourcesToKeep = utils.Where(r.Resources.ApiResources(), func(x *storage_models.ApiResource) bool {
			return x.Name == resourceIndicator
		})
	}

	apiScopesToKeep := r.Resources.ApiScopes()
	parsedScopesToKeep := r.ParsedScopes

	if strings.TrimSpace(resourceIndicator) != "" {
		// filter ApiScopes to only the ones allowed by the ApiResource requested
		scopeNamesToKeep := utils.SelectMany(apiResourcesToKeep, func(x *storage_models.ApiResource) []string {
			return x.Scopes
		})
		apiScopesToKeep = utils.Where(apiScopesToKeep, func(x *storage_models.ApiScope) bool {
			return utils.Contains(scopeNamesToKeep, x.Name)
		})

		// filter ParsedScopes to those matching the apiScopesToKeep
		parsedScopesToKeepList := utils.Where(parsedScopesToKeep, func(x *ParsedScopeValue) bool {
			return utils.Contains(scopeNamesToKeep, x.ParsedName)
		})
		if r.Resources.OfflineAccess {
			parsedScopesToKeepList = append(parsedScopesToKeepList, &ParsedScopeValue{RawValue: gois.StandardScopesOfflineAccess})
		}
		parsedScopesToKeep = parsedScopesToKeepList
	}

	resources := storage_models.NewResources(
		storage_models.WithResourcesOfflineAccess(r.Resources.OfflineAccess),
		storage_models.WithResourcesIdentityResources(r.Resources.IdentityResources()),
		storage_models.WithResourcesApiResources(apiResourcesToKeep),
		storage_models.WithResourcesApiScopes(apiScopesToKeep),
	)
	return &ResourceValidationResult{
		Resources:    resources,
		ParsedScopes: parsedScopesToKeep,
	}
}

// GetRequiredScopeValues Returns the collection of scope values that are required.
func (r *ResourceValidationResult) GetRequiredScopeValues() []string {
	names := utils.Select(
		utils.Where(r.Resources.IdentityResources(), func(x *storage_models.IdentityResource) bool {
			return x.Required
		}),
		func(x *storage_models.IdentityResource) string {
			return x.Name
		},
	)

	names = append(names, utils.Select(
		utils.Where(r.Resources.ApiScopes(), func(x *storage_models.ApiScope) bool {
			return x.Required
		}),
		func(x *storage_models.ApiScope) string {
			return x.Name
		},
	)...)

	values := utils.Select(
		utils.Where(r.ParsedScopes, func(x *ParsedScopeValue) bool {
			return utils.Contains(names, x.ParsedName)
		}),
		func(x *ParsedScopeValue) string {
			return x.RawValue
		},
	)

	return values
}
