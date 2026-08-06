// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package ciba

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// capturingUserValidator resolves every hint to a fixed subject and records
// the context it received.
type capturingUserValidator struct {
	captured *validators_models.BackchannelAuthenticationUserValidationContext
	subject  string
}

func (v *capturingUserValidator) Validate(ctx context.Context, validation *validators_models.BackchannelAuthenticationUserValidationContext) error {
	v.captured = validation
	validation.Subject = claimspkg.NewClaimsPrincipal(
		claimspkg.WithClaimsPrincipalIdentity(
			claimspkg.NewClaimsIdentity(
				claimspkg.WithAuthenticationType("test"),
				claimspkg.WithClaims([]*claimspkg.Claim{
					claimspkg.NewClaim(claimspkg.WithClaimType("sub"), claimspkg.WithClaimValue(v.subject)),
				}),
			),
		),
	)
	return nil
}

func newCibaPipeline(userValidator *capturingUserValidator) *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()
	pipeline.BackchannelAuthenticationUserValidator = userValidator

	client1 := storage_models.NewClient()
	client1.ClientId = "client1"
	if err := client1.SetAllowedGrantTypes(gois.GrantTypesBackchannelAuthentication); err != nil {
		panic(err)
	}
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	client1.ClientSecrets = []*storage_models.Secret{secret}
	client1.AllowOfflineAccess = true
	client1.AllowedScopes = []string{"openid", "profile", "scope1"}

	pipeline.Clients = []*storage_models.Client{client1}

	user := test.NewTestUser()
	user.SubjectId = "123"
	user.Username = "bob"
	user.Password = "bob"
	pipeline.Users = append(pipeline.Users, user)

	pipeline.IdentityScopes = append(pipeline.IdentityScopes,
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesProfile(),
	)

	apiScope := storage_models.NewApiScope()
	apiScope.Name = "scope1"
	pipeline.ApiScopes = append(pipeline.ApiScopes, apiScope)

	pipeline.Initialize()
	return pipeline
}

func TestBackchannelAuthenticationRejectsGet(t *testing.T) {
	a := require.New(t)

	pipeline := newCibaPipeline(&capturingUserValidator{subject: "123"})

	response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.BackchannelAuthenticationEndpoint)

	a.NoError(err)
	a.Equal(http.StatusBadRequest, response.StatusCode)
}

func TestBackchannelAuthenticationRejectsMalformedForm(t *testing.T) {
	a := require.New(t)

	pipeline := newCibaPipeline(&capturingUserValidator{subject: "123"})

	response, err := pipeline.BackChannelClient.Post(
		pipeline.TestServer.URL+integration_common.BackchannelAuthenticationEndpoint,
		"application/x-www-form-urlencoded",
		strings.NewReader("invalid"),
	)

	a.NoError(err)
	a.Equal(http.StatusBadRequest, response.StatusCode)
}

func TestBackchannelAuthenticationPassesTheLoginHintToTheUserValidator(t *testing.T) {
	a := require.New(t)

	userValidator := &capturingUserValidator{subject: "123"}
	pipeline := newCibaPipeline(userValidator)

	body := url.Values{}
	body.Add("client_id", "client1")
	body.Add("client_secret", "secret")
	body.Add("scope", "openid profile scope1 offline_access")
	body.Add("login_hint", "this means bob")

	response, err := pipeline.BackChannelClient.PostForm(pipeline.TestServer.URL+integration_common.BackchannelAuthenticationEndpoint, body)

	a.NoError(err)
	a.Equal(http.StatusOK, response.StatusCode)
	a.NotNil(userValidator.captured)
	a.Equal("this means bob", userValidator.captured.LoginHint)
	a.NotNil(userValidator.captured.Client)
	a.Equal("client1", userValidator.captured.Client.ClientId)
}
