// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// recordingConfirmation answers every call with a fixed confirmation or
// error and records what it was asked.
type recordingConfirmation struct {
	value     string
	err       error
	calls     int
	requests  []*http.Request
	clientIds []string
}

func (c *recordingConfirmation) Confirmation(_ context.Context, request *http.Request, clientId string) (string, error) {
	c.calls++
	c.requests = append(c.requests, request)
	c.clientIds = append(c.clientIds, clientId)
	return c.value, c.err
}

const boundConfirmation = `{"x5t#S256":"bound-thumbprint"}`

func confirmingTokenService(store *retainingReferenceStore, creation *capturingTokenCreation, request *http.Request, confirmation *recordingConfirmation) *TokenService {
	// A nil *recordingConfirmation must reach the service as a nil interface.
	if confirmation == nil {
		return NewTokenService(nil, store, creation, fixedClock{}, nil, config_options.NewWicketOptions(), nil, request, nil)
	}
	return NewTokenService(nil, store, creation, fixedClock{}, nil, config_options.NewWicketOptions(), nil, request, confirmation)
}

func jwtAccessToken(clientId string) *storage_models.Token {
	token := referenceAccessToken(clientId)
	token.AccessTokenType = wicket.AccessTokenTypeJwt
	return token
}

func TestCreateSecurityTokenBindsAccessTokens(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/token", nil)

	t.Run("the confirmation overwrites an earlier one", func(t *testing.T) {
		creation := &capturingTokenCreation{}
		confirmation := &recordingConfirmation{value: boundConfirmation}
		svc := confirmingTokenService(nil, creation, request, confirmation)
		token := jwtAccessToken("client-b")
		token.Confirmation = `{"x5t#S256":"stale"}`

		_, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.Equal(t, boundConfirmation, token.Confirmation)
		require.Same(t, token, creation.captured)
		require.Equal(t, 1, confirmation.calls)
		require.Same(t, request, confirmation.requests[0])
		require.Equal(t, []string{"client-b"}, confirmation.clientIds)
	})

	t.Run("an unbound answer clears an earlier confirmation", func(t *testing.T) {
		confirmation := &recordingConfirmation{}
		svc := confirmingTokenService(nil, &capturingTokenCreation{}, request, confirmation)
		token := jwtAccessToken("client-u")
		token.Confirmation = `{"x5t#S256":"stale"}`

		_, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.Empty(t, token.Confirmation)
	})

	t.Run("an identity token is not bound", func(t *testing.T) {
		confirmation := &recordingConfirmation{value: boundConfirmation}
		svc := confirmingTokenService(nil, &capturingTokenCreation{}, request, confirmation)
		token := jwtAccessToken("client-i")
		token.Type = wicket.TokenTypesIdentityToken

		_, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.Zero(t, confirmation.calls)
		require.Empty(t, token.Confirmation)
	})

	t.Run("without a confirmation seam the token is untouched", func(t *testing.T) {
		svc := confirmingTokenService(nil, &capturingTokenCreation{}, request, nil)
		token := jwtAccessToken("client-n")
		token.Confirmation = `{"x5t#S256":"kept"}`

		_, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.Equal(t, `{"x5t#S256":"kept"}`, token.Confirmation)
	})

	t.Run("an error is returned as is and nothing is issued", func(t *testing.T) {
		failure := errors.New("no certificate")
		creation := &capturingTokenCreation{}
		store := &retainingReferenceStore{}
		svc := confirmingTokenService(store, creation, request, &recordingConfirmation{err: failure})

		for _, token := range []*storage_models.Token{jwtAccessToken("client-e"), referenceAccessToken("client-e")} {
			serialized, err := svc.CreateSecurityToken(context.Background(), token)
			require.ErrorIs(t, err, failure)
			require.Empty(t, serialized)
		}
		require.Nil(t, creation.captured)
		require.Empty(t, store.handles)
	})
}

func TestReferenceTokenRecordCarriesTheConfirmationClaim(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/token", nil)

	t.Run("bound", func(t *testing.T) {
		store := &retainingReferenceStore{}
		svc := confirmingTokenService(store, &capturingTokenCreation{}, request, &recordingConfirmation{value: boundConfirmation})
		token := referenceAccessToken("client-r")
		token.Claims = append(token.Claims, claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesConfirmation),
			claimspkg.WithClaimValue("carried in"),
		))
		callerClaims := append([]*claimspkg.Claim(nil), token.Claims...)

		handle, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.NotEmpty(t, handle)
		require.Len(t, store.tokens, 1)
		stored := store.tokens[0]
		require.Equal(t, boundConfirmation, stored.Confirmation)
		var cnf []any
		for _, claim := range stored.Claims {
			if claim.Type == wicket.JwtClaimTypesConfirmation {
				cnf = append(cnf, claim.Value)
			}
		}
		require.Equal(t, []any{map[string]any{"x5t#S256": "bound-thumbprint"}}, cnf)
		require.Len(t, stored.Claims, len(callerClaims))
		require.Equal(t, callerClaims, token.Claims, "the caller's claims changed")
	})

	t.Run("unbound", func(t *testing.T) {
		store := &retainingReferenceStore{}
		svc := confirmingTokenService(store, &capturingTokenCreation{}, request, &recordingConfirmation{})
		token := referenceAccessToken("client-r")

		_, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		for _, claim := range store.tokens[0].Claims {
			require.NotEqual(t, wicket.JwtClaimTypesConfirmation, claim.Type)
		}
	})

	t.Run("a confirmation that is not an object is not stored", func(t *testing.T) {
		store := &retainingReferenceStore{}
		svc := confirmingTokenService(store, &capturingTokenCreation{}, request, &recordingConfirmation{value: `["x"]`})

		handle, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))

		require.Error(t, err)
		require.Empty(t, handle)
		require.Empty(t, store.handles)
	})
}
