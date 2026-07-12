// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package basic

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

func newCodeFlowPipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	client := storage_models.NewClient()
	client.Enabled = true
	client.ClientId = "code_client"

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha512("secret")
	client.ClientSecrets = []*storage_models.Secret{secret}

	if err := client.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{"openid"}
	client.RequireConsent = false
	client.RequirePkce = false
	client.RedirectUris = []string{"https://code_client/callback"}

	pipeline.Clients = []*storage_models.Client{client}
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	addConformanceUser(pipeline)

	pipeline.Initialize()
	return pipeline
}

func codeFlowIdToken(t *testing.T, pipeline *integration_common.WicketPipeline, state string) map[string]any {
	t.Helper()
	a := require.New(t)

	pipeline.BrowserClient.AllowAutoRedirect = false
	routePath, err := pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     "code_client",
		ResponseType: "code",
		Scope:        "openid",
		RedirectUri:  "https://code_client/callback",
		State:        state,
		Nonce:        "123_nonce",
	})
	a.NoError(err)

	response, err := pipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	authorization := pipeline.ParseAuthorizationResponseUrl(response.Header.Get("Location"))
	a.NotEmpty(authorization.Code())

	status, body := redeemCode(t, pipeline, "code_client", "secret", authorization.Code(), "https://code_client/callback", false)
	assertSuccessfulTokenResponse(t, status, body)

	return jwtPayload(t, gjson.Get(body, "id_token").String())
}

func TestCodeFlowWithoutStateOmitsTheStateHash(t *testing.T) {
	a := require.New(t)

	pipeline := newCodeFlowPipeline()
	a.NoError(pipeline.Login("bob"))

	claims := codeFlowIdToken(t, pipeline, "")

	_, present := claims["s_hash"]
	a.False(present)
}

func TestStateHashEmissionFollowsTheOption(t *testing.T) {
	for name, tc := range map[string]struct {
		emit bool
	}{
		"disabled option emits no s_hash": {emit: false},
		"enabled option emits the s_hash": {emit: true},
	} {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)

			pipeline := newCodeFlowPipeline()
			pipeline.Options.EmitStateHash = tc.emit
			a.NoError(pipeline.Login("bob"))

			state := "123_state"
			claims := codeFlowIdToken(t, pipeline, state)

			value, present := claims["s_hash"]
			if !tc.emit {
				a.False(present)
				return
			}
			a.True(present)

			digest := sha256.Sum256([]byte(state))
			expected := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
			a.Equal(expected, value)
		})
	}
}
