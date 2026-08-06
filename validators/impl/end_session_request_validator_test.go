// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"net/url"
	"testing"

	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	optmock "github.com/gonewx/wicket/config/options/mock"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/contexts"
	svcmock "github.com/gonewx/wicket/services/mock"
	storagemock "github.com/gonewx/wicket/storage/mock"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/gonewx/wicket/validators/mock"
	validators_models "github.com/gonewx/wicket/validators/models"
	"github.com/stretchr/testify/require"
)

// endSessionRequestValidatorTests  Validates end session requests.
type endSessionRequestValidatorTests struct {
	subject                       *EndSessionRequestValidator
	options                       *config_options.WicketOptions
	userSession                   *svcmock.MockUserSession
	stubTokenValidator            *mock.StubTokenValidator
	stubRedirectUriValidator      *mock.StubRedirectUriValidator
	mockLogoutNotificationService *svcmock.MockLogoutNotificationService
	mockEndSessionMessageStore    *storagemock.MockMessageStore[contexts.LogoutNotificationContext]
	user                          *claims.ClaimsPrincipal
}

func newEndSessionRequestValidatorTests() *endSessionRequestValidatorTests {

	options := optmock.NewTestWicketOptions().Create()
	stubTokenValidator := mock.NewStubTokenValidator()
	stubRedirectUriValidator := mock.NewStubRedirectUriValidator()
	mockLogoutNotificationService := svcmock.NewMockLogoutNotificationService()
	mockEndSessionMessageStore := storagemock.NewMockMessageStore[contexts.LogoutNotificationContext]()
	userSession := svcmock.NewMockUserSession()

	subject := NewEndSessionRequestValidator(
		test_common.NewTestLogger(),
		options,
		stubTokenValidator,
		stubRedirectUriValidator,
		userSession,
		mockLogoutNotificationService,
		mockEndSessionMessageStore,
	)

	instance := &endSessionRequestValidatorTests{
		options:                       options,
		subject:                       subject,
		userSession:                   userSession,
		stubTokenValidator:            stubTokenValidator,
		stubRedirectUriValidator:      stubRedirectUriValidator,
		mockLogoutNotificationService: mockLogoutNotificationService,
		mockEndSessionMessageStore:    mockEndSessionMessageStore,
	}
	instance.user, _ = models.NewLocalUser(
		models.WithLocalUserSubjectId("alice"),
	).CreatePrincipal()

	return instance
}

func TestEndSessionRequestValidatoranonymous_user_when_options_require_authenticated_user_should_return_error(t *testing.T) {
	a := require.New(t)

	instance := newEndSessionRequestValidatorTests()
	instance.options.Authentication.RequireAuthenticatedUserForSignOutMessage = true

	parameters := url.Values{}
	result, err := instance.subject.Validate(context.Background(), parameters, claims.NewClaimsPrincipal())
	a.NoError(err)
	a.Error(result.Error)

	result, err = instance.subject.Validate(context.Background(), parameters, claims.NewClaimsPrincipal(
		claims.WithClaimsPrincipalIdentity(claims.NewClaimsIdentity()),
	))
	a.NoError(err)
	a.Error(result.Error)
}

func TestEndSessionRequestValidatorvalid_params_should_return_success(t *testing.T) {
	a := require.New(t)

	instance := newEndSessionRequestValidatorTests()

	client := storage_models.NewClient()
	client.ClientId = "client"

	instance.stubTokenValidator.IdentityTokenValidationResult = &validators_models.TokenValidationResult{
		Claims: []*claims.Claim{
			claims.NewClaim(
				claims.WithClaimType("sub"),
				claims.WithClaimValue(extensions.GetSubjectIdFromPrincipal(instance.user)),
			),
		},
		Client: client,
	}
	instance.stubRedirectUriValidator.SetIsPostLogoutRedirectUriValid(true)

	parameters := url.Values{}
	parameters.Add("id_token_hint", "id_token")
	parameters.Add("post_logout_redirect_uri", "http://client/signout-cb")
	parameters.Add("client_id", "client1")
	parameters.Add("state", "foo")

	result, err := instance.subject.Validate(context.Background(), parameters, instance.user)
	a.NoError(err)
	a.NoError(result.Error)

	a.Equal("client", result.ValidatedRequest.Client.ClientId)
}

func TestEndSessionRequestValidatorno_post_logout_redirect_uri_should_not_use_single_registered_uri(t *testing.T) {
	a := require.New(t)

	instance := newEndSessionRequestValidatorTests()

	client := storage_models.NewClient()
	client.ClientId = "client1"
	client.PostLogoutRedirectUris = []string{"foo"}

	instance.stubTokenValidator.IdentityTokenValidationResult = &validators_models.TokenValidationResult{
		Claims: []*claims.Claim{
			claims.NewClaim(
				claims.WithClaimType("sub"),
				claims.WithClaimValue(extensions.GetSubjectIdFromPrincipal(instance.user)),
			),
		},
		Client: client,
	}
	instance.stubRedirectUriValidator.SetIsPostLogoutRedirectUriValid(true)

	parameters := url.Values{}
	parameters.Add("id_token_hint", "id_token")

	result, err := instance.subject.Validate(context.Background(), parameters, instance.user)
	a.NoError(err)
	a.NoError(result.Error)

	a.Empty(result.ValidatedRequest.PostLogOutUri)
}

func TestEndSessionRequestValidatorno_post_logout_redirect_uri_should_not_use_multiple_registered_uri(t *testing.T) {
	a := require.New(t)

	instance := newEndSessionRequestValidatorTests()

	client := storage_models.NewClient()
	client.ClientId = "client1"
	client.PostLogoutRedirectUris = []string{"foo", "bar"}

	instance.stubTokenValidator.IdentityTokenValidationResult = &validators_models.TokenValidationResult{
		Claims: []*claims.Claim{
			claims.NewClaim(
				claims.WithClaimType("sub"),
				claims.WithClaimValue(extensions.GetSubjectIdFromPrincipal(instance.user)),
			),
		},
		Client: client,
	}
	instance.stubRedirectUriValidator.SetIsPostLogoutRedirectUriValid(true)

	parameters := url.Values{}
	parameters.Add("id_token_hint", "id_token")

	result, err := instance.subject.Validate(context.Background(), parameters, instance.user)
	a.NoError(err)
	a.NoError(result.Error)

	a.Empty(result.ValidatedRequest.PostLogOutUri)
}

func TestEndSessionRequestValidatorpost_logout_uri_fails_validation_should_not_honor_logout_uri(t *testing.T) {
	a := require.New(t)

	instance := newEndSessionRequestValidatorTests()

	client := storage_models.NewClient()
	client.ClientId = "client"

	instance.stubTokenValidator.IdentityTokenValidationResult = &validators_models.TokenValidationResult{
		Claims: []*claims.Claim{
			claims.NewClaim(
				claims.WithClaimType("sub"),
				claims.WithClaimValue(extensions.GetSubjectIdFromPrincipal(instance.user)),
			),
		},
		Client: client,
	}
	instance.stubRedirectUriValidator.SetIsPostLogoutRedirectUriValid(false)

	parameters := url.Values{}
	parameters.Add("id_token_hint", "id_token")
	parameters.Add("post_logout_redirect_uri", "http://client/signout-cb")
	parameters.Add("client_id", "client1")
	parameters.Add("state", "foo")

	result, err := instance.subject.Validate(context.Background(), parameters, instance.user)
	a.NoError(err)
	a.NoError(result.Error)

	a.Equal("client", result.ValidatedRequest.Client.ClientId)
	a.Equal(extensions.GetSubjectIdFromPrincipal(instance.user), extensions.GetSubjectIdFromPrincipal(result.ValidatedRequest.Subject))
	a.Empty(result.ValidatedRequest.State)
	a.Empty(result.ValidatedRequest.PostLogOutUri)
}

func TestEndSessionRequestValidatorsubject_mismatch_should_return_error(t *testing.T) {
	a := require.New(t)

	instance := newEndSessionRequestValidatorTests()

	client := storage_models.NewClient()
	client.ClientId = "client"

	instance.stubTokenValidator.IdentityTokenValidationResult = &validators_models.TokenValidationResult{
		Claims: []*claims.Claim{
			claims.NewClaim(
				claims.WithClaimType("sub"),
				claims.WithClaimValue("xoxo"),
			),
		},
		Client: client,
	}
	instance.stubRedirectUriValidator.SetIsPostLogoutRedirectUriValid(true)

	parameters := url.Values{}
	parameters.Add("id_token_hint", "id_token")
	parameters.Add("post_logout_redirect_uri", "http://client/signout-cb")
	parameters.Add("client_id", "client1")
	parameters.Add("state", "foo")

	result, err := instance.subject.Validate(context.Background(), parameters, instance.user)
	a.NoError(err)
	a.Error(result.Error)
}

func TestEndSessionRequestValidatorsuccessful_request_should_return_inputs(t *testing.T) {
	a := require.New(t)

	instance := newEndSessionRequestValidatorTests()

	parameters := url.Values{}

	result, err := instance.subject.Validate(context.Background(), parameters, instance.user)
	a.NoError(err)
	a.NoError(result.Error)
	a.Equal(parameters, result.ValidatedRequest.Raw)
}
