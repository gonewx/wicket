// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// conflictClock reports a fixed instant so refresh token responses carry a
// deterministic creation time.
type conflictClock struct{}

func (conflictClock) Now() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) }

// conflictTokenService issues access tokens without touching a store.
type conflictTokenService struct{}

func (conflictTokenService) CreateAccessToken(ctx context.Context, request *responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	return &storage_models.Token{}, nil
}

func (conflictTokenService) CreateIdentityToken(ctx context.Context, request *responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	return &storage_models.Token{}, nil
}

func (conflictTokenService) CreateSecurityToken(ctx context.Context, token *storage_models.Token) (string, error) {
	return "access-token", nil
}

// versionConflictRefreshService reports a version conflict for every rotation,
// which is what a replay of an already-rotated refresh token produces.
type versionConflictRefreshService struct{}

func (versionConflictRefreshService) CreateRefreshToken(ctx context.Context, request *responses_models.RefreshTokenCreationRequest) (string, error) {
	return "", nil
}

func (versionConflictRefreshService) UpdateRefreshToken(ctx context.Context, request *responses_models.RefreshTokenUpdateRequest) (string, error) {
	return "", storage.ErrVersionConflict
}

func (versionConflictRefreshService) ValidateRefreshToken(ctx context.Context, handle string, client *storage_models.Client) *validators_models.TokenValidationResult {
	return nil
}

// TestRefreshTokenReplayMapsToInvalidGrant pins the rotation-replay protocol
// mapping: a version conflict on rotation leaves the token endpoint with
// invalid_grant (RFC 6749 section 5.2, RFC 9700 section 4.14.2), never with
// an infrastructure error.
func TestRefreshTokenReplayMapsToInvalidGrant(t *testing.T) {
	t.Parallel()

	client := storage_models.NewClient()
	client.ClientId = "client"
	client.RequireClientSecret = false
	if err := client.SetAllowedGrantTypes([]string{gois.GrantTypeRefreshToken}); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	clientStore, err := memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("client store: %v", err)
	}

	refreshToken := storage_models.NewRefreshToken()
	refreshToken.ClientId = client.ClientId
	refreshToken.Subject = claims.NewClaimsPrincipal(
		claims.WithClaimsPrincipalIdentity(
			claims.NewClaimsIdentity(
				claims.WithAuthenticationType(gois.WicketAuthenticationType),
				claims.WithClaims([]*claims.Claim{claims.NewClaim(claims.WithClaimType(gois.JwtClaimTypesSubject), claims.WithClaimValue("alice"))}),
			),
		),
	)
	refreshToken.SetAccessToken(&storage_models.Token{ClientId: client.ClientId}, "")
	refreshToken.Version = 1

	validated := validators_models.NewValidatedTokenRequest()
	validated.SetClient(client, nil, "")
	validated.GrantType = gois.GrantTypeRefreshToken
	validated.RefreshToken = refreshToken
	validated.RefreshTokenHandle = "rotated-handle"
	validated.ValidatedResources = validators_models.NewResourceValidationResult()
	validated.ValidatedResources.ParsedScopes = []*validators_models.ParsedScopeValue{{RawValue: "orders.read", ParsedName: "orders.read"}}

	generator := NewTokenResponseGenerator(
		conflictClock{},
		conflictTokenService{},
		versionConflictRefreshService{},
		validators_impl.NewScopeParser(),
		nil,
		clientStore,
		slog.Default(),
	)
	response, err := generator.Handle(context.Background(), validators_models.NewTokenRequestValidationResult(validated))
	if err == nil {
		t.Fatalf("expected error, got response %+v", response)
	}
	if !errors.Is(err, gois.TokenErrorsInvalidGrant) {
		t.Fatalf("error = %v, want wrapped gois.TokenErrorsInvalidGrant", err)
	}
	if !errors.Is(err, storage.ErrVersionConflict) {
		t.Fatalf("error = %v, want wrapped storage.ErrVersionConflict", err)
	}
}
