// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package authorize

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	client_messages "github.com/gonewx/wicket/client/messages"
	"github.com/gonewx/wicket/extensions"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	tokens_jwt "github.com/gonewx/wicket/tokens/jwt"
	"github.com/gonewx/wicket/utils"
)

type ResourceTests struct {
	mockPipeline *integration_common.WicketPipeline
	client1      *storage_models.Client
}

func newResourceTests() *ResourceTests {
	pipeline := integration_common.NewWicketPipeline()

	client1 := storage_models.NewClient()
	client1.ClientId = "client1"

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	client1.ClientSecrets = []*storage_models.Secret{secret}

	err := client1.SetAllowedGrantTypes(gois.GrantTypesCode)
	if err != nil {
		panic(err)
	}
	client1.RequireConsent = false
	client1.RequirePkce = false
	client1.AllowOfflineAccess = true

	client1.AllowedScopes = []string{"openid", "profile", "scope1", "scope2", "scope3", "scope4"}
	client1.RedirectUris = []string{"https://client1/callback"}

	client2 := storage_models.NewClient()
	client2.ClientId = "client2"
	err = client2.SetAllowedGrantTypes(gois.GrantTypesImplicit)
	if err != nil {
		panic(err)
	}
	client2.RequireConsent = false
	client2.AllowAccessTokensViaBrowser = true

	client2.AllowedScopes = []string{"openid", "profile", "scope1", "scope2", "scope3", "scope4"}
	client2.RedirectUris = []string{"https://client2/callback"}

	pipeline.Clients = []*storage_models.Client{client1, client2}

	pipeline.Users = append(pipeline.Users, test.NewTestUser())
	pipeline.Users[0].SubjectId = "bob"
	pipeline.Users[0].Username = "bob"
	pipeline.Users[0].Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("name"), claimspkg.WithClaimValue("Bob Loblaw"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("email"), claimspkg.WithClaimValue("bob@loblaw.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("role"), claimspkg.WithClaimValue("Attorney"),
		),
	}

	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesProfile())
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesEmail())

	pipeline.ApiResources = append(pipeline.ApiResources, storage_models.NewApiResource(), storage_models.NewApiResource(), storage_models.NewApiResource())
	pipeline.ApiResources[0].Name = "urn:resource1"
	pipeline.ApiResources[0].Scopes = []string{"scope1", "scope2"}
	pipeline.ApiResources[1].Name = "urn:resource2"
	pipeline.ApiResources[1].Scopes = []string{"scope2"}
	pipeline.ApiResources[2].Name = "urn:resource3"
	pipeline.ApiResources[2].RequireResourceGap = true
	pipeline.ApiResources[2].Scopes = []string{"scope3"}

	pipeline.ApiScopes = append(pipeline.ApiScopes,
		storage_models.NewApiScope(),
		storage_models.NewApiScope(),
		storage_models.NewApiScope(),
		storage_models.NewApiScope(),
	)
	pipeline.ApiScopes[0].Name = "scope1"
	pipeline.ApiScopes[1].Name = "scope2"
	pipeline.ApiScopes[2].Name = "scope3"
	pipeline.ApiScopes[3].Name = "scope4"

	pipeline.Initialize()

	return &ResourceTests{
		mockPipeline: pipeline,
		client1:      client1,
	}
}

// //////////////////////////////////////////////////////////////
// helpers
// //////////////////////////////////////////////////////////////
func parseAccessTokenClaims(a *require.Assertions, tokenResponse *client_messages.TokenResponse) []*claimspkg.Claim {
	a.False(tokenResponse.IsError())

	handler := tokens_jwt.NewSecurityTokenHandler()
	token, err := handler.ReadJwtToken(tokenResponse.AccessToken())
	a.NoError(err)
	return token.Claims()
}

func getCode(a *require.Assertions, response *http.Response) string {
	a.Equal(http.StatusFound, response.StatusCode)
	location := response.Header.Get("Location")
	idx := strings.Index(location, "code=")
	a.Greater(idx, -1)
	code := location[idx+5:]
	idx = strings.Index(code, "&")
	if idx > -1 {
		code = code[:idx]
	}
	return code
}

//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////

func TestNo_resource_indicator_on_code_exchange_should_succeed(t *testing.T) {
	a := require.New(t)

	ti := newResourceTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.BrowserClient.AllowAutoRedirect = false

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client1",
			ResponseType: "code",
			Scope:        "openid profile scope1 scope2 scope3 scope4 offline_access",
			RedirectUri:  "https://client1/callback",
		},
	)
	a.NoError(err)

	query := routePath.Query()
	query.Add("resource", "urn:resource1")
	query.Add("resource", "urn:resource3")
	routePath.RawQuery = query.Encode()

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	code := getCode(a, response)

	req := client_messages.NewAuthorizationCodeTokenRequest()
	req.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	req.TokenRequest.ProtocolRequest.ClientId = "client1"
	req.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	req.Code = code
	req.RedirectUri = "https://client1/callback"

	tokenResponse, err := extensions.RequestAuthorizationCodeToken(ti.mockPipeline.BackChannelClient, req)
	a.NoError(err)

	{
		claims := parseAccessTokenClaims(a, tokenResponse)
		a.ElementsMatch([]string{"urn:resource1", "urn:resource2"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "aud"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
		a.ElementsMatch([]string{"openid", "profile", "scope1", "scope2", "scope3", "scope4", "offline_access"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "scope"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
	}
}

func TestEmpty_resource_indicator_on_authz_endpoint_should_succeed(t *testing.T) {
	a := require.New(t)

	ti := newResourceTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.BrowserClient.AllowAutoRedirect = false

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client1",
			ResponseType: "code",
			Scope:        "openid profile scope1 scope2 scope3 scope4 offline_access",
			RedirectUri:  "https://client1/callback",
		},
	)
	a.NoError(err)

	query := routePath.Query()
	query.Add("resource", " ")
	routePath.RawQuery = query.Encode()

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	code := getCode(a, response)

	req := client_messages.NewAuthorizationCodeTokenRequest()
	req.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	req.TokenRequest.ProtocolRequest.ClientId = "client1"
	req.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	req.Code = code
	req.RedirectUri = "https://client1/callback"
	req.Parameters.Add("resource", " ")

	tokenResponse, err := extensions.RequestAuthorizationCodeToken(ti.mockPipeline.BackChannelClient, req)
	a.NoError(err)

	{
		claims := parseAccessTokenClaims(a, tokenResponse)
		a.ElementsMatch([]string{"urn:resource1", "urn:resource2"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "aud"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
		a.ElementsMatch([]string{"openid", "profile", "scope1", "scope2", "scope3", "scope4", "offline_access"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "scope"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
	}
}

func TestEmpty_resource_indicator_on_code_exchange_should_succeed(t *testing.T) {
	a := require.New(t)

	ti := newResourceTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.BrowserClient.AllowAutoRedirect = false

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client1",
			ResponseType: "code",
			Scope:        "openid profile scope1 scope2 scope3 scope4 offline_access",
			RedirectUri:  "https://client1/callback",
		},
	)
	a.NoError(err)

	query := routePath.Query()
	query.Add("resource", "urn:resource1")
	query.Add("resource", "urn:resource3")
	routePath.RawQuery = query.Encode()

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	code := getCode(a, response)

	req := client_messages.NewAuthorizationCodeTokenRequest()
	req.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	req.TokenRequest.ProtocolRequest.ClientId = "client1"
	req.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	req.Code = code
	req.RedirectUri = "https://client1/callback"
	req.Parameters.Add("resource", " ")

	tokenResponse, err := extensions.RequestAuthorizationCodeToken(ti.mockPipeline.BackChannelClient, req)
	a.NoError(err)

	{
		claims := parseAccessTokenClaims(a, tokenResponse)
		a.ElementsMatch([]string{"urn:resource1", "urn:resource2"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "aud"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
		a.ElementsMatch([]string{"openid", "profile", "scope1", "scope2", "scope3", "scope4", "offline_access"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "scope"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
	}
}

func TestResource_indicator_on_code_exchange_should_succeed(t *testing.T) {
	a := require.New(t)

	ti := newResourceTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.BrowserClient.AllowAutoRedirect = false

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client1",
			ResponseType: "code",
			Scope:        "openid profile scope1 scope2 scope3 scope4 offline_access",
			RedirectUri:  "https://client1/callback",
		},
	)
	a.NoError(err)

	query := routePath.Query()
	query.Add("resource", "urn:resource1")
	query.Add("resource", "urn:resource3")
	routePath.RawQuery = query.Encode()

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	code := getCode(a, response)

	req := client_messages.NewAuthorizationCodeTokenRequest()
	req.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	req.TokenRequest.ProtocolRequest.ClientId = "client1"
	req.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	req.Code = code
	req.RedirectUri = "https://client1/callback"
	req.Parameters.Add("resource", "urn:resource1")

	tokenResponse, err := extensions.RequestAuthorizationCodeToken(ti.mockPipeline.BackChannelClient, req)
	a.NoError(err)

	{
		claims := parseAccessTokenClaims(a, tokenResponse)
		a.ElementsMatch([]string{"urn:resource1"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "aud"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
		a.ElementsMatch([]string{"scope1", "scope2", "offline_access"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "scope"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
	}
}

func TestResource_indicator_on_refresh_token_exchange_should_succeed(t *testing.T) {
	a := require.New(t)

	ti := newResourceTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.BrowserClient.AllowAutoRedirect = false

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client1",
			ResponseType: "code",
			Scope:        "openid profile scope1 scope2 scope3 scope4 offline_access",
			RedirectUri:  "https://client1/callback",
		},
	)
	a.NoError(err)

	query := routePath.Query()
	query.Add("resource", "urn:resource1")
	query.Add("resource", "urn:resource3")
	routePath.RawQuery = query.Encode()

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	code := getCode(a, response)

	req := client_messages.NewAuthorizationCodeTokenRequest()
	req.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	req.TokenRequest.ProtocolRequest.ClientId = "client1"
	req.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	req.Code = code
	req.RedirectUri = "https://client1/callback"

	tokenResponse, err := extensions.RequestAuthorizationCodeToken(ti.mockPipeline.BackChannelClient, req)
	a.NoError(err)

	refreshTokenReq := client_messages.NewRefreshTokenRequest()

	refreshTokenReq.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	refreshTokenReq.TokenRequest.ProtocolRequest.ClientId = "client1"
	refreshTokenReq.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	refreshTokenReq.RefreshToken = tokenResponse.RefreshToken()
	refreshTokenReq.Parameters.Set("resource", "urn:resource1")

	tokenResponse, err = extensions.RequestRefreshToken(ti.mockPipeline.BackChannelClient, refreshTokenReq)
	a.NoError(err)

	{
		claims := parseAccessTokenClaims(a, tokenResponse)
		a.ElementsMatch([]string{"urn:resource1"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "aud"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
		a.ElementsMatch([]string{"scope1", "scope2", "offline_access"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "scope"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
	}
}

func TestNo_resource_indicator_on_refresh_token_exchange_should_succeed(t *testing.T) {
	a := require.New(t)

	ti := newResourceTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.BrowserClient.AllowAutoRedirect = false

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client1",
			ResponseType: "code",
			Scope:        "openid profile scope1 scope2 scope3 scope4 offline_access",
			RedirectUri:  "https://client1/callback",
		},
	)
	a.NoError(err)

	query := routePath.Query()
	query.Add("resource", "urn:resource1")
	query.Add("resource", "urn:resource3")
	routePath.RawQuery = query.Encode()

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	code := getCode(a, response)

	req := client_messages.NewAuthorizationCodeTokenRequest()
	req.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	req.TokenRequest.ProtocolRequest.ClientId = "client1"
	req.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	req.Code = code
	req.RedirectUri = "https://client1/callback"

	tokenResponse, err := extensions.RequestAuthorizationCodeToken(ti.mockPipeline.BackChannelClient, req)
	a.NoError(err)

	refreshTokenReq := client_messages.NewRefreshTokenRequest()

	refreshTokenReq.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	refreshTokenReq.TokenRequest.ProtocolRequest.ClientId = "client1"
	refreshTokenReq.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	refreshTokenReq.RefreshToken = tokenResponse.RefreshToken()

	tokenResponse, err = extensions.RequestRefreshToken(ti.mockPipeline.BackChannelClient, refreshTokenReq)
	a.NoError(err)

	{
		claims := parseAccessTokenClaims(a, tokenResponse)
		a.ElementsMatch([]string{"urn:resource1", "urn:resource2"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "aud"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
		a.ElementsMatch([]string{"openid", "profile", "scope1", "scope2", "scope3", "scope4", "offline_access"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "scope"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
	}
}

func TestResource_indicator_without_offline_access_should_succeed(t *testing.T) {
	a := require.New(t)

	ti := newResourceTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.BrowserClient.AllowAutoRedirect = false

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client1",
			ResponseType: "code",
			Scope:        "scope1 scope2",
			RedirectUri:  "https://client1/callback",
		},
	)
	a.NoError(err)

	query := routePath.Query()
	query.Add("resource", "urn:resource1")
	routePath.RawQuery = query.Encode()

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	code := getCode(a, response)

	req := client_messages.NewAuthorizationCodeTokenRequest()
	req.TokenRequest.ProtocolRequest.Address = ti.mockPipeline.TestServer.URL + integration_common.TokenEndpoint
	req.TokenRequest.ProtocolRequest.ClientId = "client1"
	req.TokenRequest.ProtocolRequest.ClientSecret = "secret"
	req.Code = code
	req.RedirectUri = "https://client1/callback"
	req.Parameters.Set("resource", "urn:resource1")

	tokenResponse, err := extensions.RequestAuthorizationCodeToken(ti.mockPipeline.BackChannelClient, req)
	a.NoError(err)

	{
		claims := parseAccessTokenClaims(a, tokenResponse)
		a.ElementsMatch([]string{"urn:resource1"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "aud"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
		a.ElementsMatch([]string{"scope1", "scope2"}, utils.Select(
			utils.Where(claims, func(c *claimspkg.Claim) bool {
				return c.Type == "scope"
			}), func(c *claimspkg.Claim) string {
				return c.Value.(string)
			}),
		)
	}
}

func TestIplicit_flow_with_resource_indicator_should_fail(t *testing.T) {
	a := require.New(t)

	ti := newResourceTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client2",
			ResponseType: "id_token token",
			Scope:        "openid profile scope1 scope2 scope3 scope4",
			Nonce:        "nonce",
			RedirectUri:  "https://client2/callback",
		},
	)
	a.NoError(err)

	query := routePath.Query()
	query.Add("resource", "urn:resource1")
	query.Add("resource", "urn:resource3")
	routePath.RawQuery = query.Encode()

	_, err = ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)
	a.True(ti.mockPipeline.ErrorWasCalled)
	a.Equal("invalid_target", ti.mockPipeline.ErrorMessage.Error)
}
