// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

var referenceHandlePattern = regexp.MustCompile(`^[0-9A-F]{64}$`)

// retainingReferenceStore keeps the very pointers it is handed, which is what
// a store is allowed to do, and can be told to refuse a write.
type retainingReferenceStore struct {
	handles []string
	tokens  []*storage_models.Token
	refuse  func(handle string) error
}

func (s *retainingReferenceStore) StoreReferenceToken(ctx context.Context, handle string, token *storage_models.Token) error {
	s.handles = append(s.handles, handle)
	if s.refuse != nil {
		return s.refuse(handle)
	}
	s.tokens = append(s.tokens, token)
	return nil
}

func (s *retainingReferenceStore) GetReferenceToken(ctx context.Context, handle string) (*storage_models.Token, error) {
	return nil, storage.ErrNotFound
}

func (s *retainingReferenceStore) RemoveReferenceToken(ctx context.Context, handle string) error {
	return nil
}

func (s *retainingReferenceStore) RemoveReferenceTokens(ctx context.Context, subjectId, clientId string) error {
	return nil
}

func (s *retainingReferenceStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return 0, nil
}

func referenceAccessToken(clientId string) *storage_models.Token {
	return &storage_models.Token{
		Type:            wicket.TokenTypesAccessToken,
		AccessTokenType: wicket.AccessTokenTypeReference,
		ClientId:        clientId,
		Issuer:          "https://issuer.example",
		CreationTime:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Lifetime:        3600,
		Audiences:       []string{"api-one", "api-two"},
		Claims: []*claimspkg.Claim{
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue("subject-1")),
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesClientId), claimspkg.WithClaimValue(clientId)),
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesScope), claimspkg.WithClaimValue("api-one")),
		},
	}
}

func newReferenceTokenService(store storage.ReferenceTokenStore, creation *capturingTokenCreation, logger *slog.Logger) *TokenService {
	return NewTokenService(nil, store, creation, fixedClock{}, nil, config_options.NewWicketOptions(), logger, nil)
}

// requireNoHandleTrace fails when text holds the handle or any eight character
// run of it, so a prefix or suffix cannot slip through either.
func requireNoHandleTrace(t *testing.T, text string, handle string) {
	t.Helper()
	require.NotEmpty(t, handle)
	for start := 0; start+8 <= len(handle); start++ {
		require.NotContains(t, text, handle[start:start+8])
	}
}

// TestCreateAccessTokenCarriesClientAndForm: the assembled access token names
// the requesting client and the access token form that client is configured
// with; without a validated request both stay at their zero value.
func TestCreateAccessTokenCarriesClientAndForm(t *testing.T) {
	svc := newReferenceTokenService(nil, nil, nil)

	t.Run("reference client", func(t *testing.T) {
		request := accessTokenRequest([]string{"api-one"}, "")
		request.ValidatedRequest.ClientId = "client-r"
		request.ValidatedRequest.AccessTokenType = wicket.AccessTokenTypeReference

		token, err := svc.CreateAccessToken(context.Background(), request)

		require.NoError(t, err)
		require.Equal(t, "client-r", token.ClientId)
		require.Equal(t, wicket.AccessTokenTypeReference, token.AccessTokenType)
	})

	t.Run("jwt client", func(t *testing.T) {
		request := accessTokenRequest([]string{"api-one"}, "")
		request.ValidatedRequest.ClientId = "client-j"
		request.ValidatedRequest.AccessTokenType = wicket.AccessTokenTypeJwt

		token, err := svc.CreateAccessToken(context.Background(), request)

		require.NoError(t, err)
		require.Equal(t, "client-j", token.ClientId)
		require.Equal(t, wicket.AccessTokenTypeJwt, token.AccessTokenType)
	})

	t.Run("no validated request", func(t *testing.T) {
		token, err := svc.CreateAccessToken(context.Background(), &responses_models.TokenCreationRequest{})

		require.NoError(t, err)
		require.Empty(t, token.ClientId)
		require.Equal(t, wicket.AccessTokenTypeJwt, token.AccessTokenType)
	})
}

// TestCreateSecurityTokenFormSelection: only an access token marked as a
// reference token is stored and answered with a handle; a JWT access token
// and an identity token are signed and never reach the store.
func TestCreateSecurityTokenFormSelection(t *testing.T) {
	t.Run("reference access token is stored and not signed", func(t *testing.T) {
		store := &retainingReferenceStore{}
		creation := &capturingTokenCreation{}
		svc := newReferenceTokenService(store, creation, nil)

		handle, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))

		require.NoError(t, err)
		require.Regexp(t, referenceHandlePattern, handle)
		require.Equal(t, []string{handle}, store.handles)
		require.Len(t, store.tokens, 1)
		require.Nil(t, creation.captured, "a reference token must not be signed")
	})

	t.Run("jwt access token is signed and the store stays untouched", func(t *testing.T) {
		store := &retainingReferenceStore{}
		creation := &capturingTokenCreation{}
		svc := newReferenceTokenService(store, creation, nil)
		token := referenceAccessToken("client-j")
		token.AccessTokenType = wicket.AccessTokenTypeJwt

		serialized, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.Equal(t, "serialized", serialized)
		require.Same(t, token, creation.captured)
		require.Empty(t, store.handles)
	})

	t.Run("jwt access token needs no store", func(t *testing.T) {
		creation := &capturingTokenCreation{}
		svc := newReferenceTokenService(nil, creation, nil)
		token := referenceAccessToken("client-j")
		token.AccessTokenType = wicket.AccessTokenTypeJwt

		serialized, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.Equal(t, "serialized", serialized)
		require.Same(t, token, creation.captured)
	})

	t.Run("identity token is signed even when marked as reference", func(t *testing.T) {
		store := &retainingReferenceStore{}
		creation := &capturingTokenCreation{}
		svc := newReferenceTokenService(store, creation, nil)
		token := referenceAccessToken("client-r")
		token.Type = wicket.TokenTypesIdentityToken

		serialized, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.Equal(t, "serialized", serialized)
		require.Same(t, token, creation.captured)
		require.Empty(t, store.handles)
	})

	t.Run("identity token marked as reference needs no store", func(t *testing.T) {
		creation := &capturingTokenCreation{}
		svc := newReferenceTokenService(nil, creation, nil)
		token := referenceAccessToken("client-r")
		token.Type = wicket.TokenTypesIdentityToken

		serialized, err := svc.CreateSecurityToken(context.Background(), token)

		require.NoError(t, err)
		require.Equal(t, "serialized", serialized)
	})
}

// TestCreateSecurityTokenReferenceJwtIdAssembly: the jwt id step applies to a
// reference token as it does to a signed one — the stored record carries a
// fresh id when the token opted in and none otherwise.
func TestCreateSecurityTokenReferenceJwtIdAssembly(t *testing.T) {
	for name, includeJwtId := range map[string]bool{"opted in": true, "not opted in": false} {
		t.Run(name, func(t *testing.T) {
			store := &retainingReferenceStore{}
			svc := newReferenceTokenService(store, &capturingTokenCreation{}, nil)
			token := referenceAccessToken("client-r")
			token.IncludeJwtId = includeJwtId

			_, err := svc.CreateSecurityToken(context.Background(), token)

			require.NoError(t, err)
			require.Len(t, store.tokens, 1)
			jwtIds := claimsOfType(store.tokens[0].Claims, wicket.JwtClaimTypesJwtId)
			if includeJwtId {
				require.Len(t, jwtIds, 1)
				require.NotEmpty(t, jwtIds[0].Value)
			} else {
				require.Empty(t, jwtIds)
			}
		})
	}
}

// TestCreateSecurityTokenStoresIndependentCopy: the store receives a complete
// record that shares no slice with the caller's model, so a store that keeps
// what it is given is unaffected when the caller reuses its model afterwards.
func TestCreateSecurityTokenStoresIndependentCopy(t *testing.T) {
	store := &retainingReferenceStore{}
	svc := newReferenceTokenService(store, &capturingTokenCreation{}, nil)
	token := referenceAccessToken("client-r")
	token.AllowedSigningAlgorithms = []string{"RS256"}

	wantCreationTime := token.CreationTime
	wantLifetime := token.Lifetime
	wantAudiences := append([]string(nil), token.Audiences...)
	wantAlgorithms := append([]string(nil), token.AllowedSigningAlgorithms...)
	wantClaims := append([]*claimspkg.Claim(nil), token.Claims...)

	_, err := svc.CreateSecurityToken(context.Background(), token)
	require.NoError(t, err)
	require.Len(t, store.tokens, 1)
	stored := store.tokens[0]

	// Control: the record is complete, field for field.
	require.NotSame(t, token, stored)
	require.Equal(t, "client-r", stored.ClientId)
	require.Equal(t, wicket.AccessTokenTypeReference, stored.AccessTokenType)
	require.Equal(t, wicket.TokenTypesAccessToken, stored.Type)
	require.Equal(t, "https://issuer.example", stored.Issuer)
	require.Equal(t, wantCreationTime, stored.CreationTime)
	require.Equal(t, wantLifetime, stored.Lifetime)
	require.Equal(t, wantAudiences, stored.Audiences)
	require.Equal(t, wantAlgorithms, stored.AllowedSigningAlgorithms)
	require.Equal(t, wantClaims, stored.Claims)
	require.Equal(t, "subject-1", stored.SubjectId())

	// The caller goes on to reuse its model.
	token.CreationTime = token.CreationTime.Add(24 * time.Hour)
	token.Lifetime = 7
	token.Audiences[0] = "rewritten"
	token.AllowedSigningAlgorithms[0] = "rewritten"
	token.Claims[0] = claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue("rewritten"))

	require.Equal(t, wantCreationTime, stored.CreationTime)
	require.Equal(t, wantLifetime, stored.Lifetime)
	require.Equal(t, wantAudiences, stored.Audiences)
	require.Equal(t, wantAlgorithms, stored.AllowedSigningAlgorithms)
	require.Equal(t, wantClaims, stored.Claims)
	require.Equal(t, "subject-1", stored.SubjectId())
}

// TestCreateSecurityTokenReferenceFailsClosed: when the record cannot be
// stored no handle is returned and no JWT is issued in its place. The error
// keeps the identity of what the store returned but none of its text, since a
// store may echo the handle it was given.
func TestCreateSecurityTokenReferenceFailsClosed(t *testing.T) {
	const marker = "store-side-detail-7f3a"

	for name, tc := range map[string]struct {
		refuse        func(handle string) error
		wantDuplicate bool
	}{
		"store reports a plain error echoing the handle": {
			refuse: func(handle string) error { return fmt.Errorf("%s: key %s rejected", marker, handle) },
		},
		"store reports a duplicate handle echoing the handle": {
			refuse: func(handle string) error {
				return fmt.Errorf("%s: key %s: %w", marker, handle, storage.ErrDuplicateHandle)
			},
			wantDuplicate: true,
		},
		"store reports the bare duplicate handle error": {
			refuse:        func(handle string) error { return storage.ErrDuplicateHandle },
			wantDuplicate: true,
		},
		"store reports a cancelled context": {
			refuse: func(handle string) error { return fmt.Errorf("%s: %w", marker, context.Canceled) },
		},
	} {
		t.Run(name, func(t *testing.T) {
			var storeError error
			store := &retainingReferenceStore{}
			store.refuse = func(handle string) error {
				storeError = tc.refuse(handle)
				return storeError
			}
			creation := &capturingTokenCreation{}
			logs := &bytes.Buffer{}
			logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			svc := newReferenceTokenService(store, creation, logger)

			result, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))

			require.Error(t, err)
			require.Empty(t, result)
			require.Nil(t, creation.captured, "a failed reference token must not fall back to a JWT")
			require.Empty(t, store.tokens)

			// Control: the store was handed a real handle.
			require.Len(t, store.handles, 1)
			handle := store.handles[0]
			require.Regexp(t, referenceHandlePattern, handle)

			require.ErrorIs(t, err, storeError)
			require.Equal(t, tc.wantDuplicate, errors.Is(err, storage.ErrDuplicateHandle))
			requireNoHandleTrace(t, err.Error(), handle)
			require.NotContains(t, err.Error(), marker)
			if strings.Contains(storeError.Error(), marker) {
				require.NotContains(t, err.Error(), storeError.Error())
			}

			// The same holds once a caller wraps the error.
			wrapped := fmt.Errorf("create token response: %w", err)
			require.ErrorIs(t, wrapped, storeError)
			require.Equal(t, tc.wantDuplicate, errors.Is(wrapped, storage.ErrDuplicateHandle))
			requireNoHandleTrace(t, wrapped.Error(), handle)
			require.NotContains(t, wrapped.Error(), marker)

			// Control: the failure was logged, without the handle or the
			// store's text.
			require.Contains(t, logs.String(), "Reference token could not be stored")
			require.Contains(t, logs.String(), "client-r")
			requireNoHandleTrace(t, logs.String(), handle)
			require.NotContains(t, logs.String(), marker)

			// The fixed text and the logged category tell a duplicate handle
			// from any other store failure.
			wantText, wantCategory := "create security token: reference token store write failed", "store_failure"
			if tc.wantDuplicate {
				wantText, wantCategory = "create security token: reference token handle already exists", "duplicate_handle"
			}
			require.Equal(t, wantText, err.Error())
			require.Contains(t, logs.String(), `"category":"`+wantCategory+`"`)
		})
	}

	t.Run("control: the echoing store error does hold the handle", func(t *testing.T) {
		var storeError error
		store := &retainingReferenceStore{refuse: func(handle string) error {
			storeError = fmt.Errorf("%s: key %s rejected", marker, handle)
			return storeError
		}}
		svc := newReferenceTokenService(store, &capturingTokenCreation{}, nil)

		_, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))

		require.Error(t, err)
		require.Len(t, store.handles, 1)
		require.Contains(t, storeError.Error(), store.handles[0])
		require.Contains(t, storeError.Error(), marker)
	})

	t.Run("control: the error text does not vary with the store error", func(t *testing.T) {
		texts := map[string]struct{}{}
		for _, detail := range []string{"first detail", "second detail"} {
			store := &retainingReferenceStore{refuse: func(handle string) error { return errors.New(detail) }}
			svc := newReferenceTokenService(store, &capturingTokenCreation{}, nil)

			_, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))

			require.Error(t, err)
			texts[err.Error()] = struct{}{}
		}
		require.Len(t, texts, 1)
	})

	t.Run("control: a store that accepts the write yields the handle", func(t *testing.T) {
		store := &retainingReferenceStore{}
		svc := newReferenceTokenService(store, &capturingTokenCreation{}, nil)

		handle, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))

		require.NoError(t, err)
		require.Equal(t, []string{handle}, store.handles)
	})

	t.Run("a failing store without a logger does not panic", func(t *testing.T) {
		store := &retainingReferenceStore{refuse: func(handle string) error { return errors.New("refused") }}
		svc := newReferenceTokenService(store, &capturingTokenCreation{}, nil)

		result, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))

		require.Error(t, err)
		require.Empty(t, result)
	})
}

// TestCreateSecurityTokenReferenceWithoutStore: a service built without a
// store cannot issue a reference token; it reports an error instead of
// panicking or signing a JWT.
func TestCreateSecurityTokenReferenceWithoutStore(t *testing.T) {
	creation := &capturingTokenCreation{}
	svc := newReferenceTokenService(nil, creation, nil)

	result, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))

	require.Error(t, err)
	require.Empty(t, result)
	require.Nil(t, creation.captured, "a missing store must not fall back to a JWT")
	require.False(t, errors.Is(err, storage.ErrDuplicateHandle))

	// Control: the same token is issued once a store is present.
	store := &retainingReferenceStore{}
	handle, err := newReferenceTokenService(store, creation, nil).CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))
	require.NoError(t, err)
	require.Regexp(t, referenceHandlePattern, handle)
	require.Nil(t, creation.captured)
}

// TestCreateSecurityTokenReferenceRequiresClientId: a reference token that
// names no client could never be validated, so it is refused before anything
// is written.
func TestCreateSecurityTokenReferenceRequiresClientId(t *testing.T) {
	store := &retainingReferenceStore{}
	creation := &capturingTokenCreation{}
	svc := newReferenceTokenService(store, creation, nil)

	result, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken(""))

	require.Error(t, err)
	require.Empty(t, result)
	require.Empty(t, store.handles, "nothing may be written for a token without a client")
	require.Nil(t, creation.captured, "a refused reference token must not fall back to a JWT")

	// Control: naming the client is all it takes.
	handle, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))
	require.NoError(t, err)
	require.Equal(t, []string{handle}, store.handles)
}

// TestCreateSecurityTokenReferenceHandlesAreFreshAndUnlogged: every issuance
// draws a new handle of the expected shape, and issuing writes no handle to
// the log.
func TestCreateSecurityTokenReferenceHandlesAreFreshAndUnlogged(t *testing.T) {
	store := &retainingReferenceStore{}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := newReferenceTokenService(store, &capturingTokenCreation{}, logger)

	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		handle, err := svc.CreateSecurityToken(context.Background(), referenceAccessToken("client-r"))
		require.NoError(t, err)
		require.Regexp(t, referenceHandlePattern, handle)
		require.NotContains(t, handle, ".")
		seen[handle] = struct{}{}
	}
	require.Len(t, seen, 64)
	require.Equal(t, 64, len(store.handles))

	for handle := range seen {
		requireNoHandleTrace(t, logs.String(), handle)
	}
}
