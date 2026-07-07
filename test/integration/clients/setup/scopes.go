// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package setup

import (
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

func GetIdentityScopes() []*storage_models.IdentityResource {
	resource := storage_models.NewIdentityResource()
	resource.Resource.Name = "roles"
	resource.UserClaims = []string{"role"}

	identityScopes := []*storage_models.IdentityResource{
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesEmail(),
		storage_models.IdentityResourcesAddress(),
		resource,
	}

	return identityScopes
}

func GetApiResources() []*storage_models.ApiResource {
	r1 := storage_models.NewApiResource()
	r1.Name = "api1"

	s1 := storage_models.NewSecret()
	s1.Value = utils.Sha256("secret")

	r1.ApiSecrets = []*storage_models.Secret{s1}
	r1.Scopes = []string{"api1", "api2", "api3", "api4.with.roles"}

	r2 := storage_models.NewApiResource()
	r2.Name = "other_api"
	r2.Scopes = []string{"other_api"}

	return []*storage_models.ApiResource{r1, r2}
}

func GetApiScopes() []*storage_models.ApiScope {
	s1 := storage_models.NewApiScope()
	s1.Name = "api1"

	s2 := storage_models.NewApiScope()
	s2.Name = "api2"

	s3 := storage_models.NewApiScope()
	s3.Name = "api3"

	s4 := storage_models.NewApiScope()
	s4.Name = "api4.with.roles"
	s4.UserClaims = []string{"role"}

	s5 := storage_models.NewApiScope()
	s5.Name = "other_api"

	return []*storage_models.ApiScope{s1, s2, s3, s4, s5}
}
