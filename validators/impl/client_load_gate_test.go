// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/clientassertion"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	validators_mock "github.com/gonewx/wicket/validators/mock"
	validators_models "github.com/gonewx/wicket/validators/models"
)

var errClientStoreDown = errors.New("client store unavailable")

// gatedClientStore serves the shared client fixtures for the first `serve`
// lookups and answers every later lookup with err.
type gatedClientStore struct {
	inner storage.ClientStore
	serve int64
	err   error
	calls atomic.Int64
}

func (s *gatedClientStore) FindClientById(ctx context.Context, id string) (*storage_models.Client, error) {
	if s.calls.Add(1) > s.serve {
		return nil, s.err
	}
	return s.inner.FindClientById(ctx, id)
}

func newGatedClientStore(t *testing.T, serve int64, err error) *gatedClientStore {
	t.Helper()
	inner, createErr := createClientStore()
	if createErr != nil {
		t.Fatalf("create client store: %v", createErr)
	}
	return &gatedClientStore{inner: inner, serve: serve, err: err}
}

func newGatedTokenValidator(clients storage.ClientStore, references storage.ReferenceTokenStore) *TokenValidator {
	options := config_options.NewWicketOptions()
	options.IssuerUri = tokenTestIssuer
	return NewTokenValidator(
		test_common.NewTestLogger(),
		options,
		services_impl.NewIssuerNameService(options),
		references,
		NewCustomTokenValidator(),
		clients,
		validators_mock.NewTestProfileService(true),
		sharedKeyMaterial(),
		nil,
		fixedTestClock{now: tokenTestNow},
	)
}

// loadErrorClasses are the three client load outcomes an existence gate tells
// apart: rejected clients become invalid tokens, store failures become errors.
func loadErrorClasses() map[string]struct {
	err      error
	rejected bool
} {
	return map[string]struct {
		err      error
		rejected bool
	}{
		"not found":             {err: storage.ErrNotFound, rejected: true},
		"invalid configuration": {err: fmt.Errorf("%w: client %q", storage.ErrInvalidClientConfiguration, "roclient"), rejected: true},
		"store failure":         {err: errClientStoreDown},
	}
}

func assertGateOutcome(t *testing.T, rejected bool, wantErr error, result *gateResult, err error) {
	t.Helper()
	if rejected {
		if err != nil {
			t.Fatalf("rejected client surfaced as error: %v", err)
		}
		if !result.invalidToken() {
			t.Fatalf("rejected client did not yield invalid_token")
		}
		return
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestTokenValidatorClassifiesClientLoadErrors(t *testing.T) {
	t.Parallel()

	creator := createDefaultTokenCreator(nil)
	client := storage_models.NewClient()
	client.ClientId = "roclient"

	accessJwt, err := creator.CreateToken(context.Background(), createAccessToken(client, "valid", 600, []string{"read"}))
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}
	// The client_id claim makes validateJwt load the client a second time.
	identity := createIdentityToken("roclient", "valid")
	identity.Claims = append(identity.Claims, claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesClientId), claimspkg.WithClaimValue("roclient")))
	identityJwt, err := creator.CreateToken(context.Background(), identity)
	if err != nil {
		t.Fatalf("create identity token: %v", err)
	}

	// Each scene names a load point and how many lookups succeed before it.
	scenes := map[string]struct {
		serve    int64
		validate func(v *TokenValidator, ctx context.Context) (*gateResult, error)
	}{
		"jwt access token client in token": {
			serve: 0,
			validate: func(v *TokenValidator, ctx context.Context) (*gateResult, error) {
				return wrap(v.ValidateAccessToken(ctx, accessJwt, ""))
			},
		},
		"jwt access token client still active": {
			serve: 1,
			validate: func(v *TokenValidator, ctx context.Context) (*gateResult, error) {
				return wrap(v.ValidateAccessToken(ctx, accessJwt, ""))
			},
		},
		"reference access token client": {
			serve: 0,
			validate: func(v *TokenValidator, ctx context.Context) (*gateResult, error) {
				return wrap(v.ValidateAccessToken(ctx, "ref-handle", ""))
			},
		},
		"reference access token client still active": {
			serve: 1,
			validate: func(v *TokenValidator, ctx context.Context) (*gateResult, error) {
				return wrap(v.ValidateAccessToken(ctx, "ref-handle", ""))
			},
		},
		"identity token client": {
			serve: 0,
			validate: func(v *TokenValidator, ctx context.Context) (*gateResult, error) {
				return wrap(v.ValidateIdentityToken(ctx, identityJwt, "roclient", true))
			},
		},
		"identity token client in token": {
			serve: 1,
			validate: func(v *TokenValidator, ctx context.Context) (*gateResult, error) {
				return wrap(v.ValidateIdentityToken(ctx, identityJwt, "roclient", true))
			},
		},
	}

	for sceneName, scene := range scenes {
		for className, class := range loadErrorClasses() {
			t.Run(sceneName+"/"+className, func(t *testing.T) {
				t.Parallel()
				references := createReferenceTokenStore()
				if err := references.StoreReferenceToken(context.Background(), "ref-handle", createAccessToken(client, "valid", 600, []string{"read"})); err != nil {
					t.Fatalf("store reference token: %v", err)
				}
				clients := newGatedClientStore(t, scene.serve, class.err)
				result, err := scene.validate(newGatedTokenValidator(clients, references), context.Background())
				if clients.calls.Load() <= scene.serve {
					t.Fatalf("load point not reached: %d lookups", clients.calls.Load())
				}
				assertGateOutcome(t, class.rejected, class.err, result, err)
				if !class.rejected && result != nil {
					t.Fatalf("store failure returned a result: %+v", result)
				}
			})
		}
	}

	t.Run("healthy store accepts", func(t *testing.T) {
		t.Parallel()
		v := newGatedTokenValidator(newGatedClientStore(t, 100, nil), createReferenceTokenStore())
		result, err := v.ValidateAccessToken(context.Background(), accessJwt, "")
		if err != nil || result.Error != nil {
			t.Fatalf("result = %+v, err = %v", result, err)
		}
	})
}

type gateResult struct{ error error }

func (r *gateResult) invalidToken() bool {
	return r != nil && errors.Is(r.error, wicket.ProtectedResourceErrorsInvalidToken)
}

func wrap(result *validators_models.TokenValidationResult, err error) (*gateResult, error) {
	if result == nil {
		return nil, err
	}
	return &gateResult{error: result.Error}, err
}

type stubSecretParser struct{ id string }

func (p stubSecretParser) Parse(*http.Request) (*models.ParsedSecret, error) {
	return &models.ParsedSecret{Id: p.id, Type: wicket.ParsedSecretTypesSharedSecret, Credential: "secret"}, nil
}

func (p stubSecretParser) GetAvailableAuthenticationMethods() []string { return nil }

func TestClientSecretValidatorClassifiesClientLoadErrors(t *testing.T) {
	t.Parallel()

	for name, class := range loadErrorClasses() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validator := NewClientSecretValidator(
				test_common.NewTestLogger(),
				newGatedClientStore(t, 0, class.err),
				nil,
				stubSecretParser{id: "roclient"},
			)
			result := validator.Validate(httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/token", nil))
			if result.Client != nil {
				t.Fatalf("client returned on a failed load: %+v", result.Client)
			}
			if class.rejected {
				if result.Error != wicket.TokenErrorsInvalidClient {
					t.Fatalf("error = %v, want invalid_client", result.Error)
				}
				return
			}
			if !errors.Is(result.Error, clientassertion.ErrAuthenticationUnavailable) || !errors.Is(result.Error, class.err) {
				t.Fatalf("error = %v, want unavailable wrapping %v", result.Error, class.err)
			}
			if errors.Is(result.Error, wicket.TokenErrorsInvalidClient) {
				t.Fatalf("store failure reported as invalid_client: %v", result.Error)
			}
		})
	}
}
