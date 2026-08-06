// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket/claims"
	storage "github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/gonewx/wicket/utils"
)

type introspectionRequestValidatorTest struct {
	subject             *IntrospectionRequestValidator
	referenceTokenStore storage.ReferenceTokenStore
}

func newIntrospectionRequestValidatorTest() *introspectionRequestValidatorTest {
	referenceTokenStore := createReferenceTokenStore()
	tokenValidator := createTokenValidator(
		withTokenValidatorStore(referenceTokenStore),
	)

	subject := NewIntrospectionRequestValidator(tokenValidator, test_common.NewTestLogger())
	return &introspectionRequestValidatorTest{
		subject:             subject,
		referenceTokenStore: referenceTokenStore,
	}
}

func TestValid_token_should_successfully_validate(t *testing.T) {
	a := require.New(t)

	ti := newIntrospectionRequestValidatorTest()

	token := &storage_models.Token{}
	token.CreationTime = tokenTestNow
	token.Issuer = "http://op"
	token.ClientId = "codeclient"
	token.Lifetime = 1000
	token.Claims = []*claims.Claim{
		claims.NewClaim(
			claims.WithClaimType("scope"),
			claims.WithClaimValue("a"),
		),
		claims.NewClaim(
			claims.WithClaimType("scope"),
			claims.WithClaimValue("b"),
		),
	}

	handle, err := ti.referenceTokenStore.StoreReferenceToken(context.Background(), token)
	a.NoError(err)

	param := url.Values{}
	param.Add("token", handle)

	result, err := ti.subject.Validate(context.Background(), param, nil)
	a.NoError(err)

	a.NoError(result.Error)
	a.True(result.IsActive)
	a.Len(result.Claims, 6)
	a.Equal(handle, result.Token)

	claimTypes := utils.Select(result.Claims, func(c *claims.Claim) string { return c.Type })
	a.Contains(claimTypes, "iss")
	a.Contains(claimTypes, "scope")
	a.Contains(claimTypes, "iat")
	a.Contains(claimTypes, "nbf")
	a.Contains(claimTypes, "exp")
}

func TestMissing_token_should_error(t *testing.T) {
	a := require.New(t)

	ti := newIntrospectionRequestValidatorTest()

	param := url.Values{}

	result, err := ti.subject.Validate(context.Background(), param, nil)
	a.NoError(err)

	a.Error(result.Error)
	a.Equal("missing_token", result.Error.Error())
	a.False(result.IsActive)
	a.Nil(result.Claims)
	a.Empty(result.Token)
}

func TestInvalid_token_should_return_inactive(t *testing.T) {
	a := require.New(t)

	ti := newIntrospectionRequestValidatorTest()

	param := url.Values{}
	param.Add("token", "invalid")

	result, err := ti.subject.Validate(context.Background(), param, nil)
	a.NoError(err)

	a.NoError(result.Error)
	a.False(result.IsActive)
	a.Nil(result.Claims)
	a.Equal("invalid", result.Token)
}
