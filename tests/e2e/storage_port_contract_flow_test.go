// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	responses_impl "github.com/gonewx/wicket/responses/impl"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type storagePortContractClock struct {
	now time.Time
}

func (c *storagePortContractClock) Now() time.Time { return c.now }

type storagePortContractFixture struct {
	tokenValidator     *validators_impl.TokenRequestValidator
	authorizationCodes *storage_impl.AuthorizationCodeStore
	refreshTokens      *storage_impl.RefreshTokenStore
	client             *storage_models.Client
	clock              *storagePortContractClock
}

func newStoragePortContractFixture(t *testing.T) *storagePortContractFixture {
	t.Helper()

	logger := slog.Default()
	options := config_options.NewWicketOptions()
	clock := &storagePortContractClock{now: time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)}
	client := newStoragePortContractClient(t)
	resourceStore := newStoragePortContractResourceStore(t)
	authorizationCodes := storage_impl.NewAuthorizationCodeStore()
	refreshTokens := storage_impl.NewRefreshTokenStore()
	refreshService := services_impl.NewRefreshTokenService(refreshTokens, services_impl.NewHandleGenerationService())
	refreshService.SetClock(clock)
	backchannelRequests := memory.NewMemoryBackchannelAuthenticationRequestStore()

	return &storagePortContractFixture{
		tokenValidator: validators_impl.NewTokenRequestValidator(
			options,
			services_impl.NewIssuerNameService(options),
			authorizationCodes,
			validators_impl.NewExtensionGrantValidator(nil, logger),
			validators_impl.NewCustomTokenRequestValidator(),
			validators_impl.NewResourceValidator(resourceStore, validators_impl.NewScopeParser(), logger),
			resourceStore,
			refreshService,
			validators_impl.NewNotSupportedResourceOwnerPasswordValidator(logger),
			services_impl.NewProfileService(logger),
			nil,
			validators_impl.NewBackchannelAuthenticationRequestIdValidator(
				backchannelRequests,
				services_impl.NewBackchannelAuthenticationThrottlingService(options, clock),
				clock,
			),
			clock,
			logger,
		),
		authorizationCodes: authorizationCodes,
		refreshTokens:      refreshTokens,
		client:             client,
		clock:              clock,
	}
}

func newStoragePortContractClient(t *testing.T) *storage_models.Client {
	t.Helper()

	client := storage_models.NewClient()
	client.ClientId = "storage-contract-client"
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.RedirectUris = []string{"https://client.example.com/callback"}
	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{"orders.read"}
	if err := client.SetAllowedGrantTypes([]string{wicket.GrantTypeAuthorizationCode, wicket.GrantTypeRefreshToken}); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	return client
}

func newStoragePortContractResourceStore(t *testing.T) *memory.MemoryResourcesStore {
	t.Helper()

	ordersScope := storage_models.NewApiScope()
	ordersScope.Name = "orders.read"
	orders := storage_models.NewApiResource()
	orders.Name = "https://resources.example.com/orders"
	orders.Scopes = []string{ordersScope.Name}

	store, err := memory.NewMemoryResourcesStore(nil, []*storage_models.ApiResource{orders}, []*storage_models.ApiScope{ordersScope})
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}
	return store
}

func (f *storagePortContractFixture) storeAuthorizationCode(t *testing.T, creationTime time.Time, lifetime int) string {
	t.Helper()

	code := storage_models.NewAuthorizationCode()
	code.ClientId = f.client.ClientId
	code.CreationTime = creationTime
	code.Lifetime = lifetime
	code.RedirectUri = f.client.RedirectUris[0]
	code.RequestedScopes = []string{"orders.read"}
	code.Subject = claimspkg.ClaimsPrincipalAnonymous()
	handle := "contract-code"
	if err := f.authorizationCodes.StoreAuthorizationCode(context.Background(), handle, code); err != nil {
		t.Fatalf("store authorization code: %v", err)
	}
	return handle
}

func (f *storagePortContractFixture) exchangeCode(t *testing.T, handle string) (*validators_models.TokenRequestValidationResult, error) {
	t.Helper()

	values := url.Values{
		wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
		wicket.TokenRequestCode:        {handle},
		wicket.TokenRequestRedirectUri: {f.client.RedirectUris[0]},
	}
	return f.tokenValidator.ValidateRequest(context.Background(), values, &validators_models.ClientSecretValidationResult{Client: f.client})
}

func (f *storagePortContractFixture) storeRefreshToken(t *testing.T, creationTime time.Time, lifetime int) string {
	t.Helper()

	token := storage_models.NewRefreshToken()
	token.ClientId = f.client.ClientId
	token.CreationTime = creationTime
	token.Lifetime = lifetime
	token.AuthorizedScopes = []string{"orders.read"}
	token.Subject = claimspkg.ClaimsPrincipalAnonymous()
	handle := "contract-refresh"
	if err := f.refreshTokens.StoreRefreshToken(context.Background(), handle, token); err != nil {
		t.Fatalf("store refresh token: %v", err)
	}
	return handle
}

func (f *storagePortContractFixture) exchangeRefreshToken(t *testing.T, handle string) (*validators_models.TokenRequestValidationResult, error) {
	t.Helper()

	values := url.Values{
		wicket.TokenRequestGrantType:    {wicket.GrantTypeRefreshToken},
		wicket.TokenRequestRefreshToken: {handle},
	}
	return f.tokenValidator.ValidateRequest(context.Background(), values, &validators_models.ClientSecretValidationResult{Client: f.client})
}

// TestAuthorizationCodeExchangeFlowE2E pins the merge-point split on the token
// endpoint: a code that was never stored, or was already consumed, maps to the
// protocol error invalid_grant through the error channel — never to a missing
// record, never to an infrastructure error.
func TestAuthorizationCodeExchangeFlowE2E(t *testing.T) {
	t.Parallel()

	t.Run("valid code exchanges successfully", func(t *testing.T) {
		t.Parallel()
		fixture := newStoragePortContractFixture(t)
		handle := fixture.storeAuthorizationCode(t, fixture.clock.now.Add(-time.Minute), 300)
		result, err := fixture.exchangeCode(t, handle)
		if err != nil {
			t.Fatalf("exchange code: %v", err)
		}
		if result.Error != nil {
			t.Fatalf("exchange error = %v, want success", result.Error)
		}
	})

	t.Run("consumed code maps to invalid_grant", func(t *testing.T) {
		t.Parallel()
		fixture := newStoragePortContractFixture(t)
		handle := fixture.storeAuthorizationCode(t, fixture.clock.now.Add(-time.Minute), 300)
		first, err := fixture.exchangeCode(t, handle)
		if err != nil || first.Error != nil {
			t.Fatalf("first exchange = (%v, %v), want success", first, err)
		}
		second, err := fixture.exchangeCode(t, handle)
		if err != nil {
			t.Fatalf("second exchange surfaced infrastructure error: %v", err)
		}
		if !errors.Is(second.Error, wicket.TokenErrorsInvalidGrant) {
			t.Fatalf("second exchange error = %v, want invalid_grant", second.Error)
		}
	})

	t.Run("unknown code maps to invalid_grant", func(t *testing.T) {
		t.Parallel()
		fixture := newStoragePortContractFixture(t)
		result, err := fixture.exchangeCode(t, "never-stored")
		if err != nil {
			t.Fatalf("unknown code surfaced infrastructure error: %v", err)
		}
		if !errors.Is(result.Error, wicket.TokenErrorsInvalidGrant) {
			t.Fatalf("unknown code error = %v, want invalid_grant", result.Error)
		}
	})
}

// TestRefreshTokenValidationFlowE2E pins the refresh-token merge-point split:
// the service reports a miss as a not-found outcome, the validator maps it to
// the protocol error, and a stored token validates successfully.
func TestRefreshTokenValidationFlowE2E(t *testing.T) {
	t.Parallel()

	t.Run("service reports miss as not-found outcome", func(t *testing.T) {
		t.Parallel()
		fixture := newStoragePortContractFixture(t)
		service := services_impl.NewRefreshTokenService(fixture.refreshTokens, services_impl.NewHandleGenerationService())
		result := service.ValidateRefreshToken(context.Background(), "missing", fixture.client)
		if result.Error == nil || !errors.Is(result.Error, storage.ErrNotFound) {
			t.Fatalf("miss error = %v, want wrapped storage.ErrNotFound", result.Error)
		}
	})

	t.Run("service validates stored token", func(t *testing.T) {
		t.Parallel()
		fixture := newStoragePortContractFixture(t)
		handle := fixture.storeRefreshToken(t, fixture.clock.now.Add(-time.Minute), 300)
		service := services_impl.NewRefreshTokenService(fixture.refreshTokens, services_impl.NewHandleGenerationService())
		service.SetClock(fixture.clock)
		result := service.ValidateRefreshToken(context.Background(), handle, fixture.client)
		if result.Error != nil {
			t.Fatalf("validate error = %v, want success", result.Error)
		}
		if result.RefreshToken == nil {
			t.Fatal("validated refresh token is nil")
		}
	})

	t.Run("unknown refresh token maps to invalid_grant", func(t *testing.T) {
		t.Parallel()
		fixture := newStoragePortContractFixture(t)
		result, err := fixture.exchangeRefreshToken(t, "never-stored")
		if err != nil {
			t.Fatalf("unknown refresh token surfaced infrastructure error: %v", err)
		}
		if !errors.Is(result.Error, wicket.TokenErrorsInvalidGrant) {
			t.Fatalf("unknown refresh token error = %v, want invalid_grant", result.Error)
		}
	})

	t.Run("stored refresh token validates through endpoint", func(t *testing.T) {
		t.Parallel()
		fixture := newStoragePortContractFixture(t)
		handle := fixture.storeRefreshToken(t, fixture.clock.now.Add(-time.Minute), 300)
		result, err := fixture.exchangeRefreshToken(t, handle)
		if err != nil {
			t.Fatalf("exchange refresh token: %v", err)
		}
		if result.Error != nil {
			t.Fatalf("exchange error = %v, want success", result.Error)
		}
	})
}

// TestTokenRevocationIdempotencyE2E pins the revocation generator's store
// merge points: a token that is not present is a miss without an error
// (Success is false; the HTTP layer still answers 200 per RFC 7009), a
// present token is removed from its store, a request without a type hint
// falls through to the refresh token store, and an infrastructure failure
// surfaces as an error.
func TestTokenRevocationIdempotencyE2E(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	referenceTokens := storage_impl.NewReferenceTokenStore()
	refreshTokens := storage_impl.NewRefreshTokenStore()
	generator := responses_impl.NewTokenRevocationResponseGenerator(referenceTokens, refreshTokens, logger)
	client := newStoragePortContractClient(t)

	newResult := func(token string, hint string) *validators_models.TokenRevocationRequestValidationResult {
		result := validators_models.NewTokenRevocationRequestValidationResult()
		result.Token = token
		result.TokenTypeHint = hint
		result.Client = client
		return result
	}

	t.Run("missing access token is a miss without error", func(t *testing.T) {
		t.Parallel()
		response, err := generator.Handle(context.Background(), newResult("missing", wicket.TokenTypeHintsAccessToken))
		if err != nil {
			t.Fatalf("revoke missing access token: %v", err)
		}
		if response.Success {
			t.Fatal("revoke missing access token reported a hit")
		}
	})

	t.Run("missing refresh token is a miss without error", func(t *testing.T) {
		t.Parallel()
		response, err := generator.Handle(context.Background(), newResult("missing", wicket.TokenTypeHintsRefreshToken))
		if err != nil {
			t.Fatalf("revoke missing refresh token: %v", err)
		}
		if response.Success {
			t.Fatal("revoke missing refresh token reported a hit")
		}
	})

	t.Run("missing token without hint is a miss without error", func(t *testing.T) {
		t.Parallel()
		isolated := responses_impl.NewTokenRevocationResponseGenerator(storage_impl.NewReferenceTokenStore(), storage_impl.NewRefreshTokenStore(), logger)
		response, err := isolated.Handle(context.Background(), newResult("missing", ""))
		if err != nil {
			t.Fatalf("revoke missing token without hint: %v", err)
		}
		if response.Success {
			t.Fatal("revoke missing token without hint reported a hit")
		}
	})

	t.Run("refresh token without hint is removed with its reference tokens", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		references := storage_impl.NewReferenceTokenStore()
		refreshes := storage_impl.NewRefreshTokenStore()
		isolated := responses_impl.NewTokenRevocationResponseGenerator(references, refreshes, logger)

		subjectClaim := claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue("alice"))
		refresh := storage_models.NewRefreshToken()
		refresh.ClientId = client.ClientId
		refresh.CreationTime = time.Date(2026, 7, 8, 8, 0, 0, 0, time.UTC)
		refresh.Lifetime = 3600
		refresh.Subject = claimspkg.NewClaimsPrincipal(claimspkg.WithClaimsPrincipalIdentity(claimspkg.NewClaimsIdentity(claimspkg.WithClaims([]*claimspkg.Claim{subjectClaim}))))
		if err := refreshes.StoreRefreshToken(ctx, "refresh-target", refresh); err != nil {
			t.Fatalf("store refresh token: %v", err)
		}
		reference := &storage_models.Token{CreationTime: refresh.CreationTime, Lifetime: 3600, ClientId: client.ClientId, Claims: []*claimspkg.Claim{subjectClaim}}
		if err := references.StoreReferenceToken(ctx, "reference-sibling", reference); err != nil {
			t.Fatalf("store reference token: %v", err)
		}

		response, err := isolated.Handle(ctx, newResult("refresh-target", ""))
		if err != nil {
			t.Fatalf("revoke refresh token without hint: %v", err)
		}
		if !response.Success {
			t.Fatal("revoke refresh token without hint reported a miss")
		}
		if _, err := refreshes.GetRefreshToken(ctx, "refresh-target"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("refresh token still present, err = %v", err)
		}
		if _, err := references.GetReferenceToken(ctx, "reference-sibling"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("reference token of the same subject and client still present, err = %v", err)
		}
	})

	t.Run("store failure surfaces as an error", func(t *testing.T) {
		t.Parallel()
		failure := errors.New("store unavailable")
		failing := responses_impl.NewTokenRevocationResponseGenerator(
			&failingReferenceTokenStore{ReferenceTokenStore: storage_impl.NewReferenceTokenStore(), err: failure},
			storage_impl.NewRefreshTokenStore(),
			logger,
		)
		for _, hint := range []string{"", wicket.TokenTypeHintsAccessToken} {
			if _, err := failing.Handle(context.Background(), newResult("any", hint)); !errors.Is(err, failure) {
				t.Fatalf("hint %q: Handle error = %v, want %v", hint, err, failure)
			}
		}
	})

	t.Run("present reference token is removed", func(t *testing.T) {
		t.Parallel()
		token := &storage_models.Token{CreationTime: time.Date(2026, 7, 8, 8, 0, 0, 0, time.UTC), Lifetime: 3600, ClientId: client.ClientId}
		handle := "revoke-target"
		if err := referenceTokens.StoreReferenceToken(context.Background(), handle, token); err != nil {
			t.Fatalf("store reference token: %v", err)
		}
		response, err := generator.Handle(context.Background(), newResult(handle, wicket.TokenTypeHintsAccessToken))
		if err != nil {
			t.Fatalf("revoke present token: %v", err)
		}
		if !response.Success {
			t.Fatal("revoke present token reported failure")
		}
		if _, err := referenceTokens.GetReferenceToken(context.Background(), handle); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("revoked token still present, err = %v", err)
		}
	})
}

// failingReferenceTokenStore reports an infrastructure failure on every read.
type failingReferenceTokenStore struct {
	storage.ReferenceTokenStore
	err error
}

func (s *failingReferenceTokenStore) GetReferenceToken(context.Context, string) (*storage_models.Token, error) {
	return nil, s.err
}

// TestRemoveExpiredReclaimsStoreFamiliesE2E exercises the reclamation entry on
// every port family with server-side lifecycle data: expired records are
// removed and report the sentinel on read, records expiring after the cutoff
// survive, and records without an expiry survive.
func TestRemoveExpiredReclaimsStoreFamiliesE2E(t *testing.T) {
	t.Parallel()

	cutoff := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	expired := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	tests := map[string]func(t *testing.T){
		"authorization codes": func(t *testing.T) {
			store := storage_impl.NewAuthorizationCodeStore()
			oldHandle := "expired-code"
			if err := store.StoreAuthorizationCode(context.Background(), oldHandle, &storage_models.AuthorizationCode{CreationTime: expired, Lifetime: 300}); err != nil {
				t.Fatal(err)
			}
			freshHandle := "fresh-code"
			if err := store.StoreAuthorizationCode(context.Background(), freshHandle, &storage_models.AuthorizationCode{CreationTime: future, Lifetime: 300}); err != nil {
				t.Fatal(err)
			}
			count, err := store.RemoveExpired(context.Background(), cutoff)
			if err != nil || count != 1 {
				t.Fatalf("RemoveExpired = (%d, %v), want (1, nil)", count, err)
			}
			if _, err := store.GetAuthorizationCode(context.Background(), oldHandle); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("expired code still present, err = %v", err)
			}
			if _, err := store.GetAuthorizationCode(context.Background(), freshHandle); err != nil {
				t.Fatalf("fresh code removed: %v", err)
			}
		},
		"refresh tokens": func(t *testing.T) {
			store := storage_impl.NewRefreshTokenStore()
			oldHandle := "expired-token"
			if err := store.StoreRefreshToken(context.Background(), oldHandle, &storage_models.RefreshToken{CreationTime: expired, Lifetime: 300}); err != nil {
				t.Fatal(err)
			}
			freshHandle := "fresh-token"
			if err := store.StoreRefreshToken(context.Background(), freshHandle, &storage_models.RefreshToken{CreationTime: future, Lifetime: 300}); err != nil {
				t.Fatal(err)
			}
			count, err := store.RemoveExpired(context.Background(), cutoff)
			if err != nil || count != 1 {
				t.Fatalf("RemoveExpired = (%d, %v), want (1, nil)", count, err)
			}
			if _, err := store.GetRefreshToken(context.Background(), oldHandle); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("expired token still present, err = %v", err)
			}
			if _, err := store.GetRefreshToken(context.Background(), freshHandle); err != nil {
				t.Fatalf("fresh token removed: %v", err)
			}
		},
		"reference tokens": func(t *testing.T) {
			store := storage_impl.NewReferenceTokenStore()
			oldHandle := "expired-reference"
			if err := store.StoreReferenceToken(context.Background(), oldHandle, &storage_models.Token{CreationTime: expired, Lifetime: 300}); err != nil {
				t.Fatal(err)
			}
			freshHandle := "fresh-reference"
			if err := store.StoreReferenceToken(context.Background(), freshHandle, &storage_models.Token{CreationTime: future, Lifetime: 300}); err != nil {
				t.Fatal(err)
			}
			count, err := store.RemoveExpired(context.Background(), cutoff)
			if err != nil || count != 1 {
				t.Fatalf("RemoveExpired = (%d, %v), want (1, nil)", count, err)
			}
			if _, err := store.GetReferenceToken(context.Background(), oldHandle); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("expired token still present, err = %v", err)
			}
			if _, err := store.GetReferenceToken(context.Background(), freshHandle); err != nil {
				t.Fatalf("fresh token removed: %v", err)
			}
		},
		"user consents": func(t *testing.T) {
			store := storage_impl.NewUserConsentStore()
			oldExpiration := expired
			futureExpiration := future
			if err := store.StoreUserConsent(context.Background(), &storage_models.Consent{SubjectId: "sub", ClientId: "old", Expiration: &oldExpiration}); err != nil {
				t.Fatal(err)
			}
			if err := store.StoreUserConsent(context.Background(), &storage_models.Consent{SubjectId: "sub", ClientId: "fresh", Expiration: &futureExpiration}); err != nil {
				t.Fatal(err)
			}
			if err := store.StoreUserConsent(context.Background(), &storage_models.Consent{SubjectId: "sub", ClientId: "no-expiry"}); err != nil {
				t.Fatal(err)
			}
			count, err := store.RemoveExpired(context.Background(), cutoff)
			if err != nil || count != 1 {
				t.Fatalf("RemoveExpired = (%d, %v), want (1, nil)", count, err)
			}
			if _, err := store.GetUserConsent(context.Background(), "sub", "old"); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("expired consent still present, err = %v", err)
			}
			if _, err := store.GetUserConsent(context.Background(), "sub", "fresh"); err != nil {
				t.Fatalf("future consent removed: %v", err)
			}
			if _, err := store.GetUserConsent(context.Background(), "sub", "no-expiry"); err != nil {
				t.Fatalf("consent without expiration removed: %v", err)
			}
		},
		"persisted grants": func(t *testing.T) {
			store := memory.NewMemoryPersistedGrantStore()
			oldExpiration := expired
			futureExpiration := future
			if err := store.Store(context.Background(), &storage_models.PersistedGrant{Key: "old", Expiration: &oldExpiration}); err != nil {
				t.Fatal(err)
			}
			if err := store.Store(context.Background(), &storage_models.PersistedGrant{Key: "fresh", Expiration: &futureExpiration}); err != nil {
				t.Fatal(err)
			}
			if err := store.Store(context.Background(), &storage_models.PersistedGrant{Key: "no-expiry"}); err != nil {
				t.Fatal(err)
			}
			count, err := store.RemoveExpired(context.Background(), cutoff)
			if err != nil || count != 1 {
				t.Fatalf("RemoveExpired = (%d, %v), want (1, nil)", count, err)
			}
			if _, err := store.Get(context.Background(), "old"); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("expired grant still present, err = %v", err)
			}
			if _, err := store.Get(context.Background(), "fresh"); err != nil {
				t.Fatalf("future grant removed: %v", err)
			}
			if _, err := store.Get(context.Background(), "no-expiry"); err != nil {
				t.Fatalf("grant without expiration removed: %v", err)
			}
		},
		"device flows": func(t *testing.T) {
			store := memory.NewMemoryDeviceFlowStore()
			old := &storage_models.DeviceCode{CreationTime: expired, Lifetime: 300}
			fresh := &storage_models.DeviceCode{CreationTime: future, Lifetime: 300}
			if err := store.StoreDeviceAuthorization(context.Background(), "dev-old", "usr-old", old); err != nil {
				t.Fatal(err)
			}
			if err := store.StoreDeviceAuthorization(context.Background(), "dev-fresh", "usr-fresh", fresh); err != nil {
				t.Fatal(err)
			}
			count, err := store.RemoveExpired(context.Background(), cutoff)
			if err != nil || count != 1 {
				t.Fatalf("RemoveExpired = (%d, %v), want (1, nil)", count, err)
			}
			if _, err := store.FindByDeviceCode(context.Background(), "dev-old"); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("expired device flow still present, err = %v", err)
			}
			if _, err := store.FindByDeviceCode(context.Background(), "dev-fresh"); err != nil {
				t.Fatalf("fresh device flow removed: %v", err)
			}
		},
		"ciba requests": func(t *testing.T) {
			store := memory.NewMemoryBackchannelAuthenticationRequestStore()
			old := &storage_models.BackchannelAuthenticationRequest{RequestId: "old", ExpirationTime: expired}
			fresh := &storage_models.BackchannelAuthenticationRequest{RequestId: "fresh", ExpirationTime: future}
			noExpiry := &storage_models.BackchannelAuthenticationRequest{RequestId: "no-expiry"}
			if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "old", old); err != nil {
				t.Fatal(err)
			}
			if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "fresh", fresh); err != nil {
				t.Fatal(err)
			}
			if err := store.StoreBackchannelAuthenticationRequest(context.Background(), "no-expiry", noExpiry); err != nil {
				t.Fatal(err)
			}
			count, err := store.RemoveExpired(context.Background(), cutoff)
			if err != nil || count != 1 {
				t.Fatalf("RemoveExpired = (%d, %v), want (1, nil)", count, err)
			}
			if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "old"); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("expired ciba request still present, err = %v", err)
			}
			if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "fresh"); err != nil {
				t.Fatalf("fresh ciba request removed: %v", err)
			}
			if _, err := store.FindBackchannelAuthenticationRequest(context.Background(), "no-expiry"); err != nil {
				t.Fatalf("ciba request without expiration removed: %v", err)
			}
		},
		"sessions": func(t *testing.T) {
			store := session.NewMemoryStore(&storagePortContractClock{now: cutoff})
			if err := store.CreateSession(context.Background(), &session.Record{SessionID: "old", SubjectID: "sub", Expires: expired}); err != nil {
				t.Fatal(err)
			}
			if err := store.CreateSession(context.Background(), &session.Record{SessionID: "fresh", SubjectID: "sub", Expires: future}); err != nil {
				t.Fatal(err)
			}
			if err := store.CreateSession(context.Background(), &session.Record{SessionID: "no-expiry", SubjectID: "sub"}); err != nil {
				t.Fatal(err)
			}
			count, err := store.DeleteExpired(context.Background(), cutoff)
			if err != nil || count != 1 {
				t.Fatalf("DeleteExpired = (%d, %v), want (1, nil)", count, err)
			}
			if _, err := store.GetSession(context.Background(), "old"); !errors.Is(err, session.ErrSessionNotFound) {
				t.Fatalf("expired session still present, err = %v", err)
			}
			if _, err := store.GetSession(context.Background(), "fresh"); err != nil {
				t.Fatalf("fresh session removed: %v", err)
			}
			if _, err := store.GetSession(context.Background(), "no-expiry"); err != nil {
				t.Fatalf("session without expiry removed: %v", err)
			}
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test(t)
		})
	}
}

// TestExpiredRecordsStillReadableE2E pins the expiry-judgement ownership
// contract through the token endpoint: the store returns an expired record on
// read (no adapter-side filtering), and the core-side clock judge rejects it
// with the protocol error.
func TestExpiredRecordsStillReadableE2E(t *testing.T) {
	t.Parallel()

	fixture := newStoragePortContractFixture(t)

	handle := fixture.storeAuthorizationCode(t, fixture.clock.now.Add(-10*time.Minute), 300)

	// The record is long past its lifetime, but the store returns it.
	stored, err := fixture.authorizationCodes.GetAuthorizationCode(context.Background(), handle)
	if err != nil {
		t.Fatalf("read expired code: %v", err)
	}
	if stored == nil {
		t.Fatal("expired code read returned nil")
	}

	// Expiry judgement is the core side's: the endpoint rejects the expired
	// code with the protocol error, not an infrastructure error.
	result, err := fixture.exchangeCode(t, handle)
	if err != nil {
		t.Fatalf("exchange expired code surfaced infrastructure error: %v", err)
	}
	if !errors.Is(result.Error, wicket.TokenErrorsInvalidGrant) {
		t.Fatalf("expired code error = %v, want invalid_grant", result.Error)
	}
}

// TestCtxCancellationPropagatesToStoresE2E pins the port contract that every
// store method takes the caller's context: a cancelled context is threaded
// through without panic or behavioural change, and a miss still reports the
// sentinel.
func TestCtxCancellationPropagatesToStoresE2E(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := storage_impl.NewAuthorizationCodeStore()
	if _, err := store.GetAuthorizationCode(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get with cancelled ctx = %v, want ErrNotFound", err)
	}
	if count, err := store.RemoveExpired(ctx, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)); err != nil || count != 0 {
		t.Fatalf("RemoveExpired with cancelled ctx = (%d, %v)", count, err)
	}

	sessions := session.NewMemoryStore(&storagePortContractClock{now: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)})
	if _, err := sessions.GetSession(ctx, "missing"); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("GetSession with cancelled ctx = %v, want ErrSessionNotFound", err)
	}
	if count, err := sessions.DeleteExpired(ctx, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)); err != nil || count != 0 {
		t.Fatalf("DeleteExpired with cancelled ctx = (%d, %v)", count, err)
	}
}
