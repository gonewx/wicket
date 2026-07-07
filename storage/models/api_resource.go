// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"fmt"

	"github.com/gonewx/wicket/utils"
)

type ApiResource struct {
	*Resource
	RequireResourceGap                  bool
	ApiSecrets                          []*Secret
	Scopes                              []string
	AllowedAccessTokenSigningAlgorithms []string
}

func NewApiResource() *ApiResource {
	return &ApiResource{
		Resource: NewResoure(),
	}
}

func FindMatchingSigningAlgorithms(apiResources []*ApiResource) ([]string, error) {
	if len(apiResources) == 0 {
		return []string{}, nil
	}

	// only one API resource request, forward the allowed signing algorithms (if any)
	if len(apiResources) == 1 {
		return utils.First(apiResources).AllowedAccessTokenSigningAlgorithms, nil
	}

	allAlgorithms := utils.Select(
		utils.Where(apiResources, func(r *ApiResource) bool {
			return len(r.AllowedAccessTokenSigningAlgorithms) > 0
		}), func(r *ApiResource) []string { return r.AllowedAccessTokenSigningAlgorithms })

	// resources need to agree on allowed signing algorithms
	if len(allAlgorithms) > 0 {
		allowedAlgorithms := utils.IntersectLists(allAlgorithms)

		if len(allowedAlgorithms) > 0 {
			return allowedAlgorithms, nil
		}

		return nil, fmt.Errorf("Signing algorithms requirements for requested resources are not compatible.")
	}

	return []string{}, nil
}
