// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type DeviceAuthorizationRequestValidatorTests struct {
	testParameters url.Values
	testClient     *storage_models.Client
}

func newDeviceAuthorizationRequestValidatorTests() *DeviceAuthorizationRequestValidatorTests {
	testParameters := url.Values{}
	testParameters.Set("scope", "resource")

	testClient := storage_models.NewClient()
	testClient.ClientId = "device_flow"
	if err := testClient.SetAllowedGrantTypes(gois.GrantTypesDeviceFlow); err != nil {
		panic(err)
	}
	testClient.AllowedScopes = []string{"openid", "profile", "resource"}
	testClient.AllowOfflineAccess = true

	return &DeviceAuthorizationRequestValidatorTests{
		testParameters: testParameters,
		testClient:     testClient,
	}
}

func TestNull_Parameter(t *testing.T) {
	r := require.New(t)

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	result := validator.ValidateRequest(context.Background(), nil, nil)
	r.Error(result.Error)
}

func TestInvalid_Protocol_Client(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()
	tests.testClient.ProtocolType = gois.ProtocolTypesSaml2p

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), tests.testParameters, clientValidationResult)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.AuthorizeErrorsUnauthorizedClient)
}

func TestInvalid_Grant_Type(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()
	err := tests.testClient.SetAllowedGrantTypes(gois.GrantTypesImplicit)
	r.NoError(err)

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), tests.testParameters, clientValidationResult)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.AuthorizeErrorsUnauthorizedClient)
}

func TestUnauthorized_Scope(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()

	parameters := url.Values{}
	parameters.Set("scope", "resource2")

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), parameters, clientValidationResult)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidScope)
}

func TestDeviceUnknown_Scope(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()

	parameters := url.Values{}
	parameters.Set("scope", uuid.New().String())

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), parameters, clientValidationResult)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidScope)
}

func TestValid_OpenId_Request(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()

	parameters := url.Values{}
	parameters.Set("scope", "openid")

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), parameters, clientValidationResult)

	r.NoError(result.Error)
	r.True(result.ValidatedRequest.IsOpenIdRequest)
	r.Contains(result.ValidatedRequest.RequestedScopes, "openid")

	resources := result.ValidatedRequest.ValidatedResources.Resources
	r.Contains(
		utils.Select(resources.IdentityResources(), func(x *storage_models.IdentityResource) string { return x.Name }),
		"openid",
	)
	r.Empty(resources.ApiResources())
	r.NotEmpty(resources.IdentityResources())
	r.Empty(resources.ApiResources())
	r.False(resources.OfflineAccess)
}

func TestValid_Resource_Request(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()

	parameters := url.Values{}
	parameters.Set("scope", "resource")

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), parameters, clientValidationResult)

	r.NoError(result.Error)
	r.False(result.ValidatedRequest.IsOpenIdRequest)
	r.Contains(result.ValidatedRequest.RequestedScopes, "resource")

	resources := result.ValidatedRequest.ValidatedResources.Resources
	r.Empty(resources.IdentityResources())
	r.Contains(
		utils.Select(resources.ApiResources(), func(x *storage_models.ApiResource) string { return x.Name }),
		"api",
	)
	r.Contains(
		utils.Select(resources.ApiScopes(), func(x *storage_models.ApiScope) string { return x.Name }),
		"resource",
	)
	r.Empty(resources.IdentityResources())
	r.NotEmpty(resources.ApiResources())
	r.NotEmpty(resources.ApiScopes())
	r.False(resources.OfflineAccess)
}

func TestValid_Mixed_Request(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()

	parameters := url.Values{}
	parameters.Set("scope", "openid resource offline_access")

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), parameters, clientValidationResult)

	r.NoError(result.Error)
	r.True(result.ValidatedRequest.IsOpenIdRequest)
	r.Contains(result.ValidatedRequest.RequestedScopes, "openid")
	r.Contains(result.ValidatedRequest.RequestedScopes, "resource")
	r.Contains(result.ValidatedRequest.RequestedScopes, "offline_access")

	resources := result.ValidatedRequest.ValidatedResources.Resources
	r.Contains(
		utils.Select(resources.IdentityResources(), func(x *storage_models.IdentityResource) string { return x.Name }),
		"openid",
	)
	r.Contains(
		utils.Select(resources.ApiResources(), func(x *storage_models.ApiResource) string { return x.Name }),
		"api",
	)
	r.Contains(
		utils.Select(resources.ApiScopes(), func(x *storage_models.ApiScope) string { return x.Name }),
		"resource",
	)
	r.NotEmpty(resources.IdentityResources())
	r.NotEmpty(resources.ApiResources())
	r.NotEmpty(resources.ApiScopes())
	r.True(resources.OfflineAccess)
}

func TestMissing_Scopes_Expect_Client_Scopes(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()

	parameters := url.Values{}

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), parameters, clientValidationResult)

	r.NoError(result.Error)
	r.True(result.ValidatedRequest.IsOpenIdRequest)
	r.Subset(result.ValidatedRequest.RequestedScopes, tests.testClient.AllowedScopes)
}

func TestMissing_Scopes_And_Client_Scopes_Empty(t *testing.T) {
	r := require.New(t)

	tests := newDeviceAuthorizationRequestValidatorTests()
	tests.testClient.AllowedScopes = []string{}

	parameters := url.Values{}

	validator, err := createDeviceAuthorizationRequestValidator()
	r.NoError(err)

	clientValidationResult := validators_models.NewClientSecretValidationResult()
	clientValidationResult.Client = tests.testClient

	result := validator.ValidateRequest(context.Background(), parameters, clientValidationResult)

	r.Error(result.Error)
	r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidScope)
}
