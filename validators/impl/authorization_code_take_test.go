// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// redemptionParameters builds the token request for exchanging handle with
// the redirect URI the code was issued for.
func redemptionParameters(handle string, code *storage_models.AuthorizationCode) url.Values {
	return url.Values{
		wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
		wicket.TokenRequestCode:        {handle},
		wicket.TokenRequestRedirectUri: {code.RedirectUri},
	}
}

// A code presented by a client it was not issued to is taken before the
// binding check, so the misuse also burns the code: the rightful client's
// later exchange is rejected too.
func TestAuthorizationCodeTakenBeforeClientBinding(t *testing.T) {
	t.Parallel()

	f := newTokenGrantFixture(t)
	code := newGrantTestAuthorizationCode("codeclient", f.now)
	handle := storeGrantTestAuthorizationCode(t, f, code)

	foreign, err := f.validator.ValidateRequest(context.Background(), redemptionParameters(handle, code), grantTestSecretResult(t, "codeclient_restricted"))
	if err != nil {
		t.Fatalf("foreign exchange infrastructure error: %v", err)
	}
	if !errors.Is(foreign.Error, wicket.TokenErrorsInvalidGrant) {
		t.Fatalf("foreign exchange error = %v, want %v", foreign.Error, wicket.TokenErrorsInvalidGrant)
	}
	if _, err := f.authorizationCodes.GetAuthorizationCode(context.Background(), handle); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("code still stored after foreign exchange: %v", err)
	}

	owner, err := f.validator.ValidateRequest(context.Background(), redemptionParameters(handle, code), grantTestSecretResult(t, "codeclient"))
	if err != nil {
		t.Fatalf("owner exchange infrastructure error: %v", err)
	}
	if !errors.Is(owner.Error, wicket.TokenErrorsInvalidGrant) {
		t.Fatalf("owner exchange after foreign use error = %v, want %v", owner.Error, wicket.TokenErrorsInvalidGrant)
	}
}

// An expired code is rejected and, because expiry is judged after the take,
// no longer present in the store.
func TestAuthorizationCodeExpiredIsRemoved(t *testing.T) {
	t.Parallel()

	f := newTokenGrantFixture(t)
	code := newGrantTestAuthorizationCode("codeclient", f.now.Add(-10*time.Minute))
	code.Lifetime = 60
	handle := storeGrantTestAuthorizationCode(t, f, code)

	result, err := f.validator.ValidateRequest(context.Background(), redemptionParameters(handle, code), grantTestSecretResult(t, "codeclient"))
	if err != nil {
		t.Fatalf("infrastructure error: %v", err)
	}
	if !errors.Is(result.Error, wicket.TokenErrorsInvalidGrant) {
		t.Fatalf("error = %v, want %v", result.Error, wicket.TokenErrorsInvalidGrant)
	}
	if _, err := f.authorizationCodes.GetAuthorizationCode(context.Background(), handle); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired code still stored after exchange: %v", err)
	}
}

var errTakeUnavailable = errors.New("take: store unavailable")

// scriptedTakeStore answers every take with a fixed error and records which
// methods the validator called. Get and Remove are not part of redemption, so
// calling them fails the test through the recorded counts.
type scriptedTakeStore struct {
	takeErr error

	mu      sync.Mutex
	takes   int
	gets    int
	removes int
}

func (s *scriptedTakeStore) StoreAuthorizationCode(context.Context, string, *storage_models.AuthorizationCode) error {
	return errors.New("unexpected store")
}

func (s *scriptedTakeStore) GetAuthorizationCode(context.Context, string) (*storage_models.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	return nil, s.takeErr
}

func (s *scriptedTakeStore) TakeAuthorizationCode(context.Context, string) (*storage_models.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.takes++
	return nil, s.takeErr
}

func (s *scriptedTakeStore) RemoveAuthorizationCode(context.Context, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removes++
	return nil
}

func (s *scriptedTakeStore) RemoveAuthorizationCodesByClient(context.Context, string) (int, error) {
	return 0, errors.New("unexpected scoped removal")
}

func (s *scriptedTakeStore) RemoveAuthorizationCodesBySession(context.Context, string) (int, error) {
	return 0, errors.New("unexpected scoped removal")
}

func (s *scriptedTakeStore) RemoveExpired(context.Context, time.Time) (int, error) {
	return 0, errors.New("unexpected reclamation")
}

func newScriptedTakeValidator(t *testing.T, store storage.AuthorizationCodeStore) *TokenRequestValidator {
	t.Helper()

	options := config_options.NewWicketOptions()
	logger := discardTestLogger()
	resourceStore, err := memory.NewMemoryResourcesStore(nil, nil, nil)
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}
	return NewTokenRequestValidator(
		options,
		services_impl.NewIssuerNameService(options),
		store,
		NewExtensionGrantValidator(nil, logger),
		NewCustomTokenRequestValidator(),
		NewResourceValidator(resourceStore, NewScopeParser(), logger),
		resourceStore,
		services_impl.NewRefreshTokenService(nil, services_impl.NewHandleGenerationService()),
		validators_mock.NewTestResourceOwnerPasswordValidator(nil, ""),
		validators_mock.NewTestProfileService(true),
		validators_mock.NewTestDeviceCodeValidator(false),
		nil,
		fixedTestClock{now: grantValidationTestNow},
		logger,
	)
}

func TestAuthorizationCodeTakeOutcomes(t *testing.T) {
	t.Parallel()

	t.Run("infrastructure failure surfaces as error", func(t *testing.T) {
		t.Parallel()

		store := &scriptedTakeStore{takeErr: errTakeUnavailable}
		validator := newScriptedTakeValidator(t, store)
		result, err := validator.ValidateRequest(context.Background(), url.Values{
			wicket.TokenRequestGrantType: {wicket.GrantTypeAuthorizationCode},
			wicket.TokenRequestCode:      {"some-code"},
		}, grantTestSecretResult(t, "codeclient"))
		if !errors.Is(err, errTakeUnavailable) {
			t.Fatalf("error = %v (result %+v), want the take failure", err, result)
		}
		if store.takes != 1 || store.gets != 0 || store.removes != 0 {
			t.Fatalf("calls take=%d get=%d remove=%d, want take=1 get=0 remove=0", store.takes, store.gets, store.removes)
		}
	})

	t.Run("miss maps to invalid_grant", func(t *testing.T) {
		t.Parallel()

		store := &scriptedTakeStore{takeErr: storage.ErrNotFound}
		validator := newScriptedTakeValidator(t, store)
		result, err := validator.ValidateRequest(context.Background(), url.Values{
			wicket.TokenRequestGrantType: {wicket.GrantTypeAuthorizationCode},
			wicket.TokenRequestCode:      {"some-code"},
		}, grantTestSecretResult(t, "codeclient"))
		if err != nil {
			t.Fatalf("infrastructure error: %v", err)
		}
		if !errors.Is(result.Error, wicket.TokenErrorsInvalidGrant) {
			t.Fatalf("error = %v, want %v", result.Error, wicket.TokenErrorsInvalidGrant)
		}
		if store.takes != 1 || store.gets != 0 || store.removes != 0 {
			t.Fatalf("calls take=%d get=%d remove=%d, want take=1 get=0 remove=0", store.takes, store.gets, store.removes)
		}
	})

	t.Run("client without code grant does not reach the take", func(t *testing.T) {
		t.Parallel()

		store := &scriptedTakeStore{takeErr: storage.ErrNotFound}
		validator := newScriptedTakeValidator(t, store)
		result, err := validator.ValidateRequest(context.Background(), url.Values{
			wicket.TokenRequestGrantType: {wicket.GrantTypeAuthorizationCode},
			wicket.TokenRequestCode:      {"some-code"},
		}, grantTestSecretResult(t, "implicitclient"))
		if err != nil {
			t.Fatalf("infrastructure error: %v", err)
		}
		if !errors.Is(result.Error, wicket.TokenErrorsUnauthorizedClient) {
			t.Fatalf("error = %v, want %v", result.Error, wicket.TokenErrorsUnauthorizedClient)
		}
		if store.takes != 0 {
			t.Fatalf("take called %d times for a client without the code grant", store.takes)
		}
	})
}
