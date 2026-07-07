// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type userInfoResponseGeneratorTests struct {
	subject            *UserInfoResponseGenerator
	mockProfileService *test_common.MockProfileService
	user               *claimspkg.ClaimsPrincipal
	client             *storage_models.Client
	resourceStore      *storage_memory.MemoryResourcesStore
	identityResources  []*storage_models.IdentityResource
	apiResources       []*storage_models.ApiResource
	apiScopes          []*storage_models.ApiScope
}

func newUserInfoResponseGeneratorTests(t *testing.T) *userInfoResponseGeneratorTests {
	a := require.New(t)

	mockProfileService := test_common.NewMockProfileService()
	client := storage_models.NewClient()
	client.ClientId = "client"

	iduser := models.NewLocalUser(
		models.WithLocalUserSubjectId("bob"),
	)
	iduser.AdditionalClaims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("foo"), claimspkg.WithClaimValue("foo1"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("foo"), claimspkg.WithClaimValue("foo2"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("bar"), claimspkg.WithClaimValue("bar1"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("bar"), claimspkg.WithClaimValue("bar2"),
		),
	}

	user, err := iduser.CreatePrincipal()
	a.NoError(err)

	identityResources := make([]*storage_models.IdentityResource, 0)
	apiResources := make([]*storage_models.ApiResource, 0)
	apiScopes := make([]*storage_models.ApiScope, 0)

	resourceStore, err := storage_memory.NewMemoryResourcesStore(
		identityResources,
		apiResources,
		apiScopes,
	)
	a.NoError(err)

	return &userInfoResponseGeneratorTests{
		subject: NewUserInfoResponseGenerator(
			test_common.NewTestLogger(),
			mockProfileService,
			resourceStore,
		),
		mockProfileService: mockProfileService,
		user:               user,
		identityResources:  identityResources,
		apiResources:       apiResources,
		apiScopes:          apiScopes,
		resourceStore:      resourceStore,
	}
}

func TestGetRequestedClaimTypes_when_no_scopes_requested_should_return_empty_claim_types(t *testing.T) {
	a := require.New(t)

	ts := newUserInfoResponseGeneratorTests(t)

	resources := ts.subject.getRequestedResources(nil)
	claims := ts.subject.getRequestedClaimTypes(resources)

	a.Equal([]string{}, claims)
}

func TestGetRequestedClaimTypes_should_return_correct_identity_claims(t *testing.T) {
	a := require.New(t)

	ts := newUserInfoResponseGeneratorTests(t)

	identityResource1 := storage_models.NewIdentityResource()
	identityResource1.Name = "id1"
	identityResource1.UserClaims = []string{"c1", "c2"}

	ts.identityResources = append(ts.identityResources, identityResource1)

	identityResource2 := storage_models.NewIdentityResource()
	identityResource2.Name = "id2"
	identityResource2.UserClaims = []string{"c2", "c3"}

	ts.identityResources = append(ts.identityResources, identityResource2)

	resourceStore, err := storage_memory.NewMemoryResourcesStore(
		ts.identityResources,
		ts.apiResources,
		ts.apiScopes,
	)
	a.NoError(err)

	ts.subject = NewUserInfoResponseGenerator(
		test_common.NewTestLogger(),
		ts.mockProfileService,
		resourceStore,
	)

	resources := ts.subject.getRequestedResources([]string{"id1", "id2", "id3"})
	claims := ts.subject.getRequestedClaimTypes(resources)

	a.ElementsMatch([]string{"c1", "c2", "c3"}, claims)
}

func TestGetRequestedClaimTypes_should_only_return_enabled_identity_claims(t *testing.T) {
	a := require.New(t)

	ts := newUserInfoResponseGeneratorTests(t)

	identityResource1 := storage_models.NewIdentityResource()
	identityResource1.Name = "id1"
	identityResource1.UserClaims = []string{"c1", "c2"}
	identityResource1.Enabled = false

	ts.identityResources = append(ts.identityResources, identityResource1)

	identityResource2 := storage_models.NewIdentityResource()
	identityResource2.Name = "id2"
	identityResource2.UserClaims = []string{"c2", "c3"}

	ts.identityResources = append(ts.identityResources, identityResource2)

	resourceStore, err := storage_memory.NewMemoryResourcesStore(
		ts.identityResources,
		ts.apiResources,
		ts.apiScopes,
	)
	a.NoError(err)

	ts.subject = NewUserInfoResponseGenerator(
		test_common.NewTestLogger(),
		ts.mockProfileService,
		resourceStore,
	)

	resources := ts.subject.getRequestedResources([]string{"id1", "id2", "id3"})
	claims := ts.subject.getRequestedClaimTypes(resources)

	a.ElementsMatch([]string{"c2", "c3"}, claims)
}

func TestProcess_should_call_profile_service_with_requested_claim_types(t *testing.T) {
	a := require.New(t)

	ts := newUserInfoResponseGeneratorTests(t)

	identityResource1 := storage_models.NewIdentityResource()
	identityResource1.Name = "id1"
	identityResource1.UserClaims = []string{"foo"}

	ts.identityResources = append(ts.identityResources, identityResource1)

	identityResource2 := storage_models.NewIdentityResource()
	identityResource2.Name = "id2"
	identityResource2.UserClaims = []string{"bar"}

	ts.identityResources = append(ts.identityResources, identityResource2)

	result := validators_models.NewUserInfoRequestValidationResult()
	result.Subject = ts.user
	result.TokenValidationResult = validators_models.NewTokenValidationResult()
	result.TokenValidationResult.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id1"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id2"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id3"),
		),
	}
	result.TokenValidationResult.Client = ts.client

	resourceStore, err := storage_memory.NewMemoryResourcesStore(
		ts.identityResources,
		ts.apiResources,
		ts.apiScopes,
	)
	a.NoError(err)

	ts.subject = NewUserInfoResponseGenerator(
		test_common.NewTestLogger(),
		ts.mockProfileService,
		resourceStore,
	)
	_, err = ts.subject.Handle(result)
	a.NoError(err)

	a.True(ts.mockProfileService.GetProfileWasCalled())
	a.ElementsMatch([]string{"foo", "bar"}, ts.mockProfileService.ProfileContext.RequestedClaimTypes)
}

func TestProcess_should_return_claims_issued_by_profile_service(t *testing.T) {
	a := require.New(t)

	ts := newUserInfoResponseGeneratorTests(t)

	identityResource1 := storage_models.NewIdentityResource()
	identityResource1.Name = "id1"
	identityResource1.UserClaims = []string{"foo"}

	ts.identityResources = append(ts.identityResources, identityResource1)

	identityResource2 := storage_models.NewIdentityResource()
	identityResource2.Name = "id2"
	identityResource2.UserClaims = []string{"bar"}

	ts.identityResources = append(ts.identityResources, identityResource2)

	address := map[string]any{
		"street_address": "One Hacker Way",
		"locality":       "Heidelberg",
		"postal_code":    float64(69118),
		"country":        "Germany",
	}

	addr, err := json.Marshal(address)
	a.NoError(err)

	ts.mockProfileService.ProfileClaims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("email"),
			claimspkg.WithClaimValue("fred@gmail.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("name"),
			claimspkg.WithClaimValue("fred jones"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("address"),
			claimspkg.WithClaimValue("{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("address2"),
			claimspkg.WithClaimValue(addr),
		),
	}

	result := validators_models.NewUserInfoRequestValidationResult()
	result.Subject = ts.user
	result.TokenValidationResult = validators_models.NewTokenValidationResult()
	result.TokenValidationResult.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id1"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id2"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id3"),
		),
	}
	result.TokenValidationResult.Client = ts.client

	resourceStore, err := storage_memory.NewMemoryResourcesStore(
		ts.identityResources,
		ts.apiResources,
		ts.apiScopes,
	)
	a.NoError(err)

	ts.subject = NewUserInfoResponseGenerator(
		test_common.NewTestLogger(),
		ts.mockProfileService,
		resourceStore,
	)
	claims, err := ts.subject.Handle(result)
	a.NoError(err)

	a.Contains(claims, "email")
	a.Equal("fred@gmail.com", claims["email"].(string))
	a.Contains(claims, "name")
	a.Equal("fred jones", claims["name"].(string))

	// this will be treated as a string because this is not valid JSON from the System.Text library point of view
	a.Contains(claims, "address")
	a.Equal("{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }", claims["address"].(string))

	// this is a JsonElement
	a.Contains(claims, "address2")

	var resultAddress2 map[string]any
	err = json.Unmarshal(claims["address2"].([]byte), &resultAddress2)
	a.NoError(err)
	a.EqualValues(address, resultAddress2)

}

func TestProcess_should_return_sub_from_user(t *testing.T) {
	a := require.New(t)

	ts := newUserInfoResponseGeneratorTests(t)

	identityResource1 := storage_models.NewIdentityResource()
	identityResource1.Name = "id1"
	identityResource1.UserClaims = []string{"foo"}

	ts.identityResources = append(ts.identityResources, identityResource1)

	identityResource2 := storage_models.NewIdentityResource()
	identityResource2.Name = "id2"
	identityResource2.UserClaims = []string{"bar"}

	ts.identityResources = append(ts.identityResources, identityResource2)

	result := validators_models.NewUserInfoRequestValidationResult()
	result.Subject = ts.user
	result.TokenValidationResult = validators_models.NewTokenValidationResult()
	result.TokenValidationResult.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id1"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id2"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id3"),
		),
	}
	result.TokenValidationResult.Client = ts.client

	resourceStore, err := storage_memory.NewMemoryResourcesStore(
		ts.identityResources,
		ts.apiResources,
		ts.apiScopes,
	)
	a.NoError(err)

	ts.subject = NewUserInfoResponseGenerator(
		test_common.NewTestLogger(),
		ts.mockProfileService,
		resourceStore,
	)
	claims, err := ts.subject.Handle(result)
	a.NoError(err)

	a.Contains(claims, "sub")
	a.Equal("bob", claims["sub"].(string))
}

func TestProcess_should_throw_if_incorrect_sub_issued_by_profile_service(t *testing.T) {
	a := require.New(t)

	ts := newUserInfoResponseGeneratorTests(t)

	identityResource1 := storage_models.NewIdentityResource()
	identityResource1.Name = "id1"
	identityResource1.UserClaims = []string{"foo"}

	ts.identityResources = append(ts.identityResources, identityResource1)

	identityResource2 := storage_models.NewIdentityResource()
	identityResource2.Name = "id2"
	identityResource2.UserClaims = []string{"bar"}

	ts.identityResources = append(ts.identityResources, identityResource2)

	ts.mockProfileService.ProfileClaims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("sub"),
			claimspkg.WithClaimValue("fred"),
		),
	}

	result := validators_models.NewUserInfoRequestValidationResult()
	result.Subject = ts.user
	result.TokenValidationResult = validators_models.NewTokenValidationResult()
	result.TokenValidationResult.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id1"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id2"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("scope"),
			claimspkg.WithClaimValue("id3"),
		),
	}
	result.TokenValidationResult.Client = ts.client

	resourceStore, err := storage_memory.NewMemoryResourcesStore(
		ts.identityResources,
		ts.apiResources,
		ts.apiScopes,
	)
	a.NoError(err)

	ts.subject = NewUserInfoResponseGenerator(
		test_common.NewTestLogger(),
		ts.mockProfileService,
		resourceStore,
	)
	_, err = ts.subject.Handle(result)
	a.Error(err)
	a.ErrorIs(err, gois.InvalidOperationException)
	a.Contains(err.Error(), "subject")
}
