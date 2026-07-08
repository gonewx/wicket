// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type cibaResponseClock struct{}

func (cibaResponseClock) Now() time.Time { return time.Date(2026, 7, 8, 8, 0, 0, 0, time.UTC) }

type cibaTokenService struct{}

func (cibaTokenService) CreateAccessToken(*responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	return &storage_models.Token{}, nil
}

func (cibaTokenService) CreateIdentityToken(*responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	return &storage_models.Token{}, nil
}

func (cibaTokenService) CreateSecurityToken(*storage_models.Token) (string, error) {
	return "access-token", nil
}

type cibaRefreshTokenService struct{}

func (cibaRefreshTokenService) CreateRefreshToken(*responses_models.RefreshTokenCreationRequest) (string, error) {
	return "", nil
}

func (cibaRefreshTokenService) UpdateRefreshToken(*responses_models.RefreshTokenUpdateRequest) (string, error) {
	return "", nil
}

func (cibaRefreshTokenService) ValidateRefreshToken(string, *storage_models.Client) *validators_models.TokenValidationResult {
	return nil
}

func TestBackchannelAuthenticationTokenResponseConsumesRequest(t *testing.T) {
	t.Parallel()

	client := storage_models.NewClient()
	client.ClientId = "client"
	client.RequireClientSecret = false
	if err := client.SetAllowedGrantTypes(gois.GrantTypesBackchannelAuthentication); err != nil {
		t.Fatalf("set grants: %v", err)
	}
	clientStore, err := memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	requestStore := memory.NewMemoryBackchannelAuthenticationRequestStore()
	subject := claims.NewClaimsPrincipal(
		claims.WithClaimsPrincipalIdentity(
			claims.NewClaimsIdentity(
				claims.WithAuthenticationType(gois.WicketAuthenticationType),
				claims.WithClaims([]*claims.Claim{claims.NewClaim(claims.WithClaimType(gois.JwtClaimTypesSubject), claims.WithClaimValue("alice"))}),
			),
		),
	)
	state := &storage_models.BackchannelAuthenticationRequest{
		RequestId:       "request-id",
		ClientId:        client.ClientId,
		Subject:         subject,
		RequestedScopes: []string{gois.StandardScopesOpenId},
		Status:          storage_models.BackchannelAuthenticationRequestStatusApproved,
		ExpirationTime:  time.Now().Add(time.Minute),
	}
	if err := requestStore.StoreBackchannelAuthenticationRequest(state.RequestId, state); err != nil {
		t.Fatalf("store request: %v", err)
	}
	validated := validators_models.NewValidatedTokenRequest()
	validated.SetClient(client, nil, "")
	validated.GrantType = gois.GrantTypeBackchannelAuthentication
	validated.Subject = subject
	validated.BackchannelAuthenticationRequest = state
	validated.ValidatedResources = validators_models.NewResourceValidationResult()
	validated.ValidatedResources.ParsedScopes = []*validators_models.ParsedScopeValue{{RawValue: gois.StandardScopesOpenId, ParsedName: gois.StandardScopesOpenId}}

	generator := NewTokenResponseGeneratorWithBackchannelRequests(
		cibaResponseClock{},
		cibaTokenService{},
		cibaRefreshTokenService{},
		validators_impl.NewScopeParser(),
		nil,
		clientStore,
		requestStore,
		slog.Default(),
	)
	response, err := generator.Handle(validators_models.NewTokenRequestValidationResult(validated))
	if err != nil {
		t.Fatalf("handle response: %v", err)
	}
	if response.AccessToken != "access-token" {
		t.Fatalf("access token = %q", response.AccessToken)
	}
	stored, err := requestStore.FindBackchannelAuthenticationRequest(state.RequestId)
	if err != nil {
		t.Fatalf("find request: %v", err)
	}
	if stored.Status != storage_models.BackchannelAuthenticationRequestStatusConsumed {
		t.Fatalf("status = %q, want consumed", stored.Status)
	}
}
