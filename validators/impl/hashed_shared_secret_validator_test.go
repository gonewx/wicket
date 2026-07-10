// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/stretchr/testify/require"
)

// hashedSharedSecretValidatorTests Validates a shared secret stored in SHA256 or SHA512
type hashedSharedSecretValidatorTests struct {
	validator *HashedSharedSecretValidator
	clients   *storage_memory.MemoryClientStore
}

func newHashedSharedSecretValidatorTests() *hashedSharedSecretValidatorTests {
	clients, _ := storage_memory.NewMemoryClientStore(clientValidationTestClients())

	return &hashedSharedSecretValidatorTests{
		validator: NewHashedSharedSecretValidator(test_common.NewTestLogger()),
		clients:   clients,
	}
}

func TestValid_Single_Secret(t *testing.T) {
	a := require.New(t)

	ti := newHashedSharedSecretValidatorTests()

	clientId := "single_secret_hashed_no_expiration"
	client, err := extensions.FindEnabledClientById(ti.clients, clientId)
	a.NoError(err)

	secret := &models.ParsedSecret{
		Id:         clientId,
		Credential: "secret",
		Type:       gois.ParsedSecretTypesSharedSecret,
	}

	result, err := ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)

	a.True(result.Success)
}

func TestInvalid_Credential_Type(t *testing.T) {
	a := require.New(t)

	ti := newHashedSharedSecretValidatorTests()

	clientId := "single_secret_hashed_no_expiration"
	client, err := extensions.FindEnabledClientById(ti.clients, clientId)
	a.NoError(err)

	secret := &models.ParsedSecret{
		Id:         clientId,
		Credential: "secret",
		Type:       "invalid",
	}

	result, err := ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)

	a.False(result.Success)
}

func TestValid_Multiple_Secrets(t *testing.T) {
	a := require.New(t)

	ti := newHashedSharedSecretValidatorTests()

	clientId := "multiple_secrets_hashed"
	client, err := extensions.FindEnabledClientById(ti.clients, clientId)
	a.NoError(err)

	secret := &models.ParsedSecret{
		Id:         clientId,
		Credential: "secret",
		Type:       gois.ParsedSecretTypesSharedSecret,
	}

	result, err := ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)
	a.True(result.Success)

	secret.Credential = "foobar"
	result, err = ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)
	a.True(result.Success)

	secret.Credential = "quux"
	result, err = ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)
	a.True(result.Success)

	secret.Credential = "notexpired"
	result, err = ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)
	a.True(result.Success)
}

func TestInvalid_Single_Secret(t *testing.T) {
	a := require.New(t)

	ti := newHashedSharedSecretValidatorTests()

	clientId := "single_secret_hashed_no_expiration"
	client, err := extensions.FindEnabledClientById(ti.clients, clientId)
	a.NoError(err)

	secret := &models.ParsedSecret{
		Id:         clientId,
		Credential: "invalid",
		Type:       gois.ParsedSecretTypesSharedSecret,
	}

	result, err := ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)

	a.False(result.Success)
}

func TestInvalid_Multiple_Secrets(t *testing.T) {
	a := require.New(t)

	ti := newHashedSharedSecretValidatorTests()

	clientId := "multiple_secrets_hashed"
	client, err := extensions.FindEnabledClientById(ti.clients, clientId)
	a.NoError(err)

	secret := &models.ParsedSecret{
		Id:         clientId,
		Credential: "invalid",
		Type:       gois.ParsedSecretTypesSharedSecret,
	}

	result, err := ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)

	a.False(result.Success)
}

func TestClient_with_no_Secret_Should_Fail(t *testing.T) {
	a := require.New(t)

	ti := newHashedSharedSecretValidatorTests()

	clientId := "no_secret_client"
	client, err := extensions.FindEnabledClientById(ti.clients, clientId)
	a.NoError(err)

	secret := &models.ParsedSecret{
		Id:   clientId,
		Type: gois.ParsedSecretTypesSharedSecret,
	}

	result, err := ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)

	a.False(result.Success)
}

func TestClient_with_null_Secret_Should_Fail(t *testing.T) {
	a := require.New(t)

	ti := newHashedSharedSecretValidatorTests()

	clientId := "null_secret_client"
	client, err := extensions.FindEnabledClientById(ti.clients, clientId)
	a.NoError(err)

	secret := &models.ParsedSecret{
		Id:         clientId,
		Type:       gois.ParsedSecretTypesSharedSecret,
		Credential: "secret",
	}

	result, err := ti.validator.Validate(client.ClientSecrets, secret)
	a.NoError(err)

	a.False(result.Success)
}
