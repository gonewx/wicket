// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models"
	storage "github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_mock "github.com/gonewx/wicket/validators/mock"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// deviceCodeValidatorTests Allows inserting custom validation logic into token requests
type deviceCodeValidatorTests struct {
	clients    storage.ClientStore
	deviceCode *storage_models.DeviceCode
}

func newDeviceCodeValidatorTests() *deviceCodeValidatorTests {
	clients, _ := createClientStore()

	deviceCode := storage_models.NewDeviceCode()
	deviceCode.ClientId = "device_flow"
	deviceCode.IsAuthorized = true
	deviceCode.Subject, _ = models.NewLocalUser(
		models.WithLocalUserSubjectId("alice"),
	).CreatePrincipal()
	deviceCode.IsOpenId = true
	deviceCode.Lifetime = 300
	deviceCode.CreationTime = deviceCodeTestNow
	deviceCode.AuthorizedScopes = []string{"openid", "profile", "resource"}
	return &deviceCodeValidatorTests{
		clients:    clients,
		deviceCode: deviceCode,
	}
}

func TestDeviceCode_Missing(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	client, err := tests.clients.FindClientById(context.Background(), "device_flow")
	r.NoError(err)

	service := createDeviceCodeService()

	validator := createDeviceCodeValidator(service, nil, nil, nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(client, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: "",
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.Error(validation.Result.Error)
	r.ErrorIs(validation.Result.Error, gois.TokenErrorsInvalidGrant)
}

func TestDeviceCode_From_Different_Client(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	badActor, err := tests.clients.FindClientById(context.Background(), "codeclient")
	r.NoError(err)

	service := createDeviceCodeService()

	handle, err := service.StoreDeviceAuthorization(context.Background(), uuid.New().String(), tests.deviceCode)
	r.NoError(err)

	validator := createDeviceCodeValidator(service, nil, nil, nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(badActor, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: handle,
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.Error(validation.Result.Error)
	r.ErrorIs(validation.Result.Error, gois.TokenErrorsInvalidGrant)
}

func TestExpired_DeviceCode(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	tests.deviceCode.CreationTime = deviceCodeTestNow.Add(-10 * 24 * time.Hour)
	tests.deviceCode.Lifetime = 300

	client, err := tests.clients.FindClientById(context.Background(), "device_flow")
	r.NoError(err)

	service := createDeviceCodeService()

	handle, err := service.StoreDeviceAuthorization(context.Background(), uuid.New().String(), tests.deviceCode)
	r.NoError(err)

	validator := createDeviceCodeValidator(service, nil, nil, nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(client, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: handle,
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.Error(validation.Result.Error)
	r.ErrorIs(validation.Result.Error, gois.TokenErrorsExpiredToken)
}

func TestAccess_Denied(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	tests.deviceCode.AuthorizedScopes = []string{}

	client, err := tests.clients.FindClientById(context.Background(), "device_flow")
	r.NoError(err)

	service := createDeviceCodeService()

	handle, err := service.StoreDeviceAuthorization(context.Background(), uuid.New().String(), tests.deviceCode)
	r.NoError(err)

	validator := createDeviceCodeValidator(service, nil, nil, nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(client, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: handle,
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.Error(validation.Result.Error)
	r.ErrorIs(validation.Result.Error, gois.TokenErrorsAccessDenied)
}

func TestDeviceCode_Not_Yet_Authorized(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	tests.deviceCode.IsAuthorized = false

	client, err := tests.clients.FindClientById(context.Background(), "device_flow")
	r.NoError(err)

	service := createDeviceCodeService()

	handle, err := service.StoreDeviceAuthorization(context.Background(), uuid.New().String(), tests.deviceCode)
	r.NoError(err)

	validator := createDeviceCodeValidator(service, nil, nil, nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(client, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: handle,
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.Error(validation.Result.Error)
	r.ErrorIs(validation.Result.Error, gois.TokenErrorsAuthorizationPending)
}

func TestDeviceCode_Missing_Subject(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	tests.deviceCode.Subject = nil

	client, err := tests.clients.FindClientById(context.Background(), "device_flow")
	r.NoError(err)

	service := createDeviceCodeService()

	handle, err := service.StoreDeviceAuthorization(context.Background(), uuid.New().String(), tests.deviceCode)
	r.NoError(err)

	validator := createDeviceCodeValidator(service, nil, nil, nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(client, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: handle,
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.Error(validation.Result.Error)
	r.ErrorIs(validation.Result.Error, gois.TokenErrorsAuthorizationPending)
}

func TestUser_Disabled(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	client, err := tests.clients.FindClientById(context.Background(), "device_flow")
	r.NoError(err)

	service := createDeviceCodeService()

	handle, err := service.StoreDeviceAuthorization(context.Background(), uuid.New().String(), tests.deviceCode)
	r.NoError(err)

	validator := createDeviceCodeValidator(service, validators_mock.NewTestProfileService(false), nil, nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(client, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: handle,
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.Error(validation.Result.Error)
	r.ErrorIs(validation.Result.Error, gois.TokenErrorsInvalidGrant)
}

func TestDeviceCode_Polling_Too_Fast(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	client, err := tests.clients.FindClientById(context.Background(), "device_flow")
	r.NoError(err)

	service := createDeviceCodeService()

	handle, err := service.StoreDeviceAuthorization(context.Background(), uuid.New().String(), tests.deviceCode)
	r.NoError(err)

	validator := createDeviceCodeValidator(service, nil, validators_mock.NewTestDeviceFlowThrottlingService(true), nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(client, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: handle,
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.Error(validation.Result.Error)
	r.ErrorIs(validation.Result.Error, gois.TokenErrorsSlowDown)
}

func TestValid_DeviceCode(t *testing.T) {
	r := require.New(t)

	tests := newDeviceCodeValidatorTests()

	client, err := tests.clients.FindClientById(context.Background(), "device_flow")
	r.NoError(err)

	service := createDeviceCodeService()

	handle, err := service.StoreDeviceAuthorization(context.Background(), uuid.New().String(), tests.deviceCode)
	r.NoError(err)

	validator := createDeviceCodeValidator(service, nil, nil, nil)

	request := validators_models.NewValidatedTokenRequest()
	request.SetClient(client, nil, "")

	validation := &validators_models.DeviceCodeValidationContext{
		DeviceCode: handle,
		Request:    request,
	}

	err = validator.Validate(context.Background(), validation)
	r.NoError(err)

	r.NoError(validation.Result.Error)
}
