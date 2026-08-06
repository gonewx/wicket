// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	responses_impl "github.com/gonewx/wicket/responses/impl"
	responses_models "github.com/gonewx/wicket/responses/models"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// e2eTokenCreationStub issues serialized token strings without touching a
// signing stack; token serialization is outside the scope of the write- and
// concurrency-semantics flows under test.
type e2eTokenCreationStub struct{}

func (e2eTokenCreationStub) CreateAccessToken(ctx context.Context, request *responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	return &storage_models.Token{}, nil
}

func (e2eTokenCreationStub) CreateIdentityToken(ctx context.Context, request *responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	return &storage_models.Token{}, nil
}

func (e2eTokenCreationStub) CreateSecurityToken(ctx context.Context, token *storage_models.Token) (string, error) {
	return "serialized-token", nil
}

func newMemoryClientStore(t *testing.T, clients ...*storage_models.Client) *memory.MemoryClientStore {
	t.Helper()

	store, err := memory.NewMemoryClientStore(clients)
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	return store
}

// TestRefreshTokenIssuanceUsesCallerVisibleHandleE2E pins the handle-upshift
// contract through the real issuance service: the service generates the
// handle, the store records the token under exactly that handle with version 1
// written back to the caller, and no foreign key resolves to the token.
func TestRefreshTokenIssuanceUsesCallerVisibleHandleE2E(t *testing.T) {
	t.Parallel()

	fixture := newStoragePortContractFixture(t)
	service := services_impl.NewRefreshTokenService(fixture.refreshTokens, services_impl.NewHandleGenerationService())

	handle, err := service.CreateRefreshToken(context.Background(), &responses_models.RefreshTokenCreationRequest{
		Client:           fixture.client,
		Subject:          claimspkg.ClaimsPrincipalAnonymous(),
		AuthorizedScopes: []string{"orders.read"},
	})
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if handle == "" {
		t.Fatal("issued handle is empty")
	}

	stored, err := fixture.refreshTokens.GetRefreshToken(context.Background(), handle)
	if err != nil {
		t.Fatalf("read issued handle: %v", err)
	}
	if stored.ClientId != fixture.client.ClientId {
		t.Fatalf("stored client = %q, want %q", stored.ClientId, fixture.client.ClientId)
	}
	if stored.Version != 1 {
		t.Fatalf("stored version = %d, want 1", stored.Version)
	}

	if _, err := fixture.refreshTokens.GetRefreshToken(context.Background(), "not-the-issued-handle"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("read under foreign handle = %v, want storage.ErrNotFound", err)
	}
}

// TestAuthorizationCodeIssuanceStoresResponseHandleE2E pins the code-flow
// issuance path: the handle the authorize endpoint hands back to the client is
// exactly the key under which the code is stored, and a second issuance never
// collides with the first.
func TestAuthorizationCodeIssuanceStoresResponseHandleE2E(t *testing.T) {
	t.Parallel()

	fixture := newStoragePortContractFixture(t)
	generator := responses_impl.NewAuthorizeResponseGenerator(
		config_options.NewWicketOptions(),
		fixture.clock,
		e2eTokenCreationStub{},
		nil, // no state hash emission for this flow
		fixture.authorizationCodes,
		services_impl.NewHandleGenerationService(),
		slog.Default(),
	)

	newRequest := func() *validators_models.ValidatedAuthorizeRequest {
		request := validators_models.NewValidatedAuthorizeRequest()
		request.GrantType = gois.GrantTypeAuthorizationCode
		request.Client = fixture.client
		request.ClientId = fixture.client.ClientId
		request.Subject = claimspkg.ClaimsPrincipalAnonymous()
		request.RedirectUri = fixture.client.RedirectUris[0]
		return request
	}

	first, err := generator.Create(context.Background(), newRequest())
	if err != nil {
		t.Fatalf("create first code: %v", err)
	}
	if first.Code == "" {
		t.Fatal("first response carries no code")
	}

	stored, err := fixture.authorizationCodes.GetAuthorizationCode(context.Background(), first.Code)
	if err != nil {
		t.Fatalf("read code under response handle: %v", err)
	}
	if stored.ClientId != fixture.client.ClientId {
		t.Fatalf("stored client = %q, want %q", stored.ClientId, fixture.client.ClientId)
	}

	second, err := generator.Create(context.Background(), newRequest())
	if err != nil {
		t.Fatalf("create second code: %v", err)
	}
	if second.Code == first.Code {
		t.Fatal("second issuance reused the first handle")
	}
}

// TestRefreshTokenRotationLifecycleE2E pins the optimistic-concurrency
// rotation contract through the real endpoint path: two validations of the
// same handle yield independent token copies, the first rotation succeeds and
// increments the stored version, and rotation of the stale copy fails with
// invalid_grant wrapping the version-conflict sentinel (RFC 6749 section 5.2).
func TestRefreshTokenRotationLifecycleE2E(t *testing.T) {
	t.Parallel()

	fixture := newStoragePortContractFixture(t)
	refreshService := services_impl.NewRefreshTokenService(fixture.refreshTokens, services_impl.NewHandleGenerationService())
	generator := responses_impl.NewTokenResponseGenerator(
		fixture.clock,
		e2eTokenCreationStub{},
		refreshService,
		validators_impl.NewScopeParser(),
		newStoragePortContractResourceStore(t),
		newMemoryClientStore(t, fixture.client),
		slog.Default(),
	)

	handle, err := refreshService.CreateRefreshToken(context.Background(), &responses_models.RefreshTokenCreationRequest{
		Client:           fixture.client,
		Subject:          claimspkg.ClaimsPrincipalAnonymous(),
		AuthorizedScopes: []string{"orders.read"},
	})
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	first, err := fixture.exchangeRefreshToken(t, handle)
	if err != nil || first.Error != nil {
		t.Fatalf("first validation = (%v, %v), want success", first, err)
	}
	stale, err := fixture.exchangeRefreshToken(t, handle)
	if err != nil || stale.Error != nil {
		t.Fatalf("second validation = (%v, %v), want success", stale, err)
	}
	if stale.ValidatedRequest.RefreshToken == first.ValidatedRequest.RefreshToken {
		t.Fatal("validations share the same refresh token copy")
	}

	response, err := generator.Handle(context.Background(), first)
	if err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if response.RefreshToken != handle {
		t.Fatalf("rotated handle = %q, want %q", response.RefreshToken, handle)
	}
	stored, err := fixture.refreshTokens.GetRefreshToken(context.Background(), handle)
	if err != nil {
		t.Fatalf("read after rotation: %v", err)
	}
	if stored.Version != 2 {
		t.Fatalf("stored version after rotation = %d, want 2", stored.Version)
	}

	_, err = generator.Handle(context.Background(), stale)
	if err == nil {
		t.Fatal("stale rotation succeeded, want invalid_grant")
	}
	if !errors.Is(err, gois.TokenErrorsInvalidGrant) {
		t.Fatalf("stale rotation error = %v, want invalid_grant", err)
	}
	if !errors.Is(err, storage.ErrVersionConflict) {
		t.Fatalf("stale rotation error = %v, want wrapped storage.ErrVersionConflict", err)
	}
}

// TestDeviceFlowIssuanceUsesCallerVisibleHandleE2E pins the device-code
// issuance path: the service generates the device code and the store records
// the flow under exactly that code, addressable by device code and user code.
func TestDeviceFlowIssuanceUsesCallerVisibleHandleE2E(t *testing.T) {
	t.Parallel()

	store := memory.NewMemoryDeviceFlowStore()
	service := services_impl.NewDeviceFlowCodeService(store, services_impl.NewHandleGenerationService())
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	deviceCode, err := service.StoreDeviceAuthorization(context.Background(), "user-code", &storage_models.DeviceCode{
		CreationTime: now,
		Lifetime:     300,
		ClientId:     "client",
	})
	if err != nil {
		t.Fatalf("store device authorization: %v", err)
	}
	if deviceCode == "" {
		t.Fatal("issued device code is empty")
	}

	if _, err := store.FindByDeviceCode(context.Background(), deviceCode); err != nil {
		t.Fatalf("find by device code: %v", err)
	}
	if _, err := store.FindByUserCode(context.Background(), "user-code"); err != nil {
		t.Fatalf("find by user code: %v", err)
	}
	if _, err := store.FindByDeviceCode(context.Background(), "not-the-issued-code"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("find under foreign device code = %v, want storage.ErrNotFound", err)
	}
}
