// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"testing"

	"github.com/stretchr/testify/require"

	wicket_dpop "github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

// newRotationScene is a scene with DPoP enabled, the public client and the
// given refresh token consumption declared.
func newRotationScene(t *testing.T, consumption services.RefreshTokenConsumption) *scene {
	t.Helper()
	s := &scene{t: t, pipeline: integration_common.NewWicketPipeline(), registry: newCountingRegistry()}

	public := client(publicClientId)
	public.RequireClientSecret = false
	s.pipeline.Clients = append(s.pipeline.Clients, public)

	s.pipeline.IdentityScopes = append(s.pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())
	api := storage_models.NewApiResource()
	api.Name = apiName
	apiSecret := storage_models.NewSecret()
	apiSecret.Value = utils.Sha256(sharedSecret)
	api.ApiSecrets = []*storage_models.Secret{apiSecret}
	api.Scopes = []string{scopeName}
	s.pipeline.ApiResources = append(s.pipeline.ApiResources, api)
	apiScope := storage_models.NewApiScope()
	apiScope.Name = scopeName
	s.pipeline.ApiScopes = append(s.pipeline.ApiScopes, apiScope)

	user := test.NewTestUser()
	user.SubjectId = subjectId
	user.Username = userName
	user.Password = userName
	s.pipeline.Users = append(s.pipeline.Users, user)

	cfg := s.pipeline.Root.ServerConfig()
	cfg.SetReplayRegistry(s.registry)
	cfg.EnableDPoP(wicket_dpop.Options{SigningAlgorithms: []string{"ES256", "PS256"}})
	cfg.SetRefreshTokenConsumption(consumption)
	s.pipeline.Initialize()
	t.Cleanup(s.pipeline.TestServer.Close)
	return s
}

// A refresh token issued in place of a redeemed one keeps the proof key
// binding of the redeemed token (refresh token consumption, matrix #12).
func TestRotatedRefreshTokenKeepsTheProofKeyBinding(t *testing.T) {
	for name, consumption := range map[string]services.RefreshTokenConsumption{
		"removed": services.RefreshTokenRemovedOnRedemption,
		"marked":  services.RefreshTokenMarkedOnRedemption,
	} {
		t.Run(name, func(t *testing.T) {
			s := newRotationScene(t, consumption)
			key := newProofKey(t)
			other := newProofKey(t)

			issued := s.token(passwordRequest(publicClientId), s.proof(key, proofSpec{}))
			s.requireIssued("issue", issued, false)
			refreshToken := issued.field("refresh_token")
			require.NotEmpty(t, refreshToken)

			refreshed := s.token(refreshRequest(publicClientId, refreshToken), s.proof(key, proofSpec{}))
			require.Equal(t, key.thumbprint(), s.requireIssued("rotate", refreshed, false)["jkt"])
			rotated := refreshed.field("refresh_token")
			require.NotEmpty(t, rotated)
			require.NotEqual(t, refreshToken, rotated)

			requireError(t, "rotated without proof", s.token(refreshRequest(publicClientId, rotated)), "invalid_grant")
			requireError(t, "rotated with another key", s.token(refreshRequest(publicClientId, rotated), s.proof(other, proofSpec{})), "invalid_grant")
			again := s.token(refreshRequest(publicClientId, rotated), s.proof(key, proofSpec{}))
			require.Equal(t, key.thumbprint(), s.requireIssued("rotated with the same key", again, false)["jkt"])
		})
	}
}
