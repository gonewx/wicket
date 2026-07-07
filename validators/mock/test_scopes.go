// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	storage_models "github.com/gonewx/wicket/storage/models"
)

type TestScopes struct {
}

func (t *TestScopes) GetIdentity() []*storage_models.IdentityResource {
	return []*storage_models.IdentityResource{
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesProfile(),
	}
}

func (t *TestScopes) GetApis() []*storage_models.ApiResource {
	r1 := storage_models.NewApiResource()
	r1.Name = "api"
	r1.Scopes = []string{"resource", "resource2"}

	r2 := storage_models.NewApiResource()
	r2.Name = "urn:api1"
	r2.Scopes = []string{"scope1"}

	r3 := storage_models.NewApiResource()
	r3.Name = "urn:api2"
	r3.Scopes = []string{"scope1"}

	r4 := storage_models.NewApiResource()
	r4.Name = "urn:api3"
	r4.Scopes = []string{"scope1"}

	return []*storage_models.ApiResource{r1, r2, r3, r4}
}

func (t *TestScopes) GetScopes() []*storage_models.ApiScope {
	s1 := storage_models.NewApiScope()
	s1.Name = "resource"
	s1.DisplayName = "resource scope"

	s2 := storage_models.NewApiScope()
	s2.Name = "resource2"
	s2.DisplayName = "resource scope"

	s3 := storage_models.NewApiScope()
	s3.Name = "scope1"

	return []*storage_models.ApiScope{s1, s2, s3}
}
