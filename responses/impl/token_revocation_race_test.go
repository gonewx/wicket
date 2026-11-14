// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// The revocation generator reads a token, checks its client, then removes it.
// A concurrent revocation of the same token can remove the record between the
// read and the removal. The port contract makes a removal of an absent handle
// (and a subject/client batch removal that matches nothing) return nil, so the
// losing request still reports success instead of an error the endpoint would
// surface as a server failure.

const (
	raceClientId  = "race-client"
	raceSubjectId = "race-subject"
	raceHandle    = "race-handle"
)

func raceSubject() *claims.ClaimsPrincipal {
	return claims.NewClaimsPrincipal(claims.WithClaimsPrincipalIdentity(claims.NewClaimsIdentity(
		claims.WithAuthenticationType("test"),
		claims.WithClaims([]*claims.Claim{claims.NewClaim(
			claims.WithClaimType(wicket.JwtClaimTypesSubject),
			claims.WithClaimValue(raceSubjectId),
		)}),
	)))
}

func raceReferenceToken() *storage_models.Token {
	return &storage_models.Token{
		CreationTime: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		Lifetime:     3600,
		Type:         "reference",
		ClientId:     raceClientId,
		Claims: []*claims.Claim{claims.NewClaim(
			claims.WithClaimType(wicket.JwtClaimTypesSubject),
			claims.WithClaimValue(raceSubjectId),
		)},
	}
}

func raceValidationResult(hint string) *validators_models.TokenRevocationRequestValidationResult {
	client := storage_models.NewClient()
	client.ClientId = raceClientId
	return &validators_models.TokenRevocationRequestValidationResult{
		TokenTypeHint: hint,
		Token:         raceHandle,
		Client:        client,
	}
}

func raceLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// lateReferenceTokens serves reads from the real in-memory store and, right
// after a read hits, lets a competing revocation delete the records. It
// records every removal the generator performs and the error each returned.
type lateReferenceTokens struct {
	*storage_impl.ReferenceTokenStore
	competeOnRead bool

	removeErrs      []error
	batchRemoveErrs []error
}

func (s *lateReferenceTokens) GetReferenceToken(ctx context.Context, handle string) (*storage_models.Token, error) {
	token, err := s.ReferenceTokenStore.GetReferenceToken(ctx, handle)
	if err == nil && s.competeOnRead {
		if err := s.ReferenceTokenStore.RemoveReferenceToken(ctx, handle); err != nil {
			return nil, err
		}
	}
	return token, err
}

func (s *lateReferenceTokens) RemoveReferenceToken(ctx context.Context, handle string) error {
	err := s.ReferenceTokenStore.RemoveReferenceToken(ctx, handle)
	s.removeErrs = append(s.removeErrs, err)
	return err
}

func (s *lateReferenceTokens) RemoveReferenceTokens(ctx context.Context, subjectId, clientId string) error {
	err := s.ReferenceTokenStore.RemoveReferenceTokens(ctx, subjectId, clientId)
	s.batchRemoveErrs = append(s.batchRemoveErrs, err)
	return err
}

// lateRefreshTokens serves reads from the real in-memory store and, right
// after a read hits, lets a competing revocation remove the refresh token and
// the pair's reference tokens, exactly as the generator itself would.
type lateRefreshTokens struct {
	*storage_impl.RefreshTokenStore
	references *storage_impl.ReferenceTokenStore

	removeErrs []error
}

func (s *lateRefreshTokens) GetRefreshToken(ctx context.Context, handle string) (*storage_models.RefreshToken, error) {
	token, err := s.RefreshTokenStore.GetRefreshToken(ctx, handle)
	if err != nil {
		return nil, err
	}
	if err := s.RefreshTokenStore.RemoveRefreshToken(ctx, handle); err != nil {
		return nil, err
	}
	if err := s.references.RemoveReferenceTokens(ctx, token.SubjectId(), token.ClientId); err != nil {
		return nil, err
	}
	return token, nil
}

func (s *lateRefreshTokens) RemoveRefreshToken(ctx context.Context, handle string) error {
	err := s.RefreshTokenStore.RemoveRefreshToken(ctx, handle)
	s.removeErrs = append(s.removeErrs, err)
	return err
}

func TestTokenRevocationRefreshTokenRemovedConcurrently(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	referenceStore := storage_impl.NewReferenceTokenStore()
	if err := referenceStore.StoreReferenceToken(ctx, "access-handle", raceReferenceToken()); err != nil {
		t.Fatalf("store reference token: %v", err)
	}
	refreshStore := storage_impl.NewRefreshTokenStore()
	refresh := storage_models.NewRefreshToken()
	refresh.ClientId = raceClientId
	refresh.Subject = raceSubject()
	refresh.CreationTime = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	refresh.Lifetime = 3600
	if err := refreshStore.StoreRefreshToken(ctx, raceHandle, refresh); err != nil {
		t.Fatalf("store refresh token: %v", err)
	}

	references := &lateReferenceTokens{ReferenceTokenStore: referenceStore}
	refreshes := &lateRefreshTokens{RefreshTokenStore: refreshStore, references: referenceStore}
	generator := NewTokenRevocationResponseGenerator(references, refreshes, raceLogger())

	response, err := generator.Handle(ctx, raceValidationResult(wicket.TokenTypeHintsRefreshToken))
	if err != nil {
		t.Fatalf("revocation losing the race returned error: %v", err)
	}
	if response == nil || !response.Success {
		t.Fatalf("response = %+v, want Success", response)
	}
	if len(refreshes.removeErrs) != 1 || refreshes.removeErrs[0] != nil {
		t.Fatalf("RemoveRefreshToken results = %v, want one nil", refreshes.removeErrs)
	}
	if len(references.batchRemoveErrs) != 1 || references.batchRemoveErrs[0] != nil {
		t.Fatalf("RemoveReferenceTokens results = %v, want one nil", references.batchRemoveErrs)
	}
	if _, err := referenceStore.GetReferenceToken(ctx, "access-handle"); err == nil {
		t.Fatal("pair reference token survived revocation")
	}
}

func TestTokenRevocationReferenceTokenRemovedConcurrently(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	referenceStore := storage_impl.NewReferenceTokenStore()
	if err := referenceStore.StoreReferenceToken(ctx, raceHandle, raceReferenceToken()); err != nil {
		t.Fatalf("store reference token: %v", err)
	}
	references := &lateReferenceTokens{ReferenceTokenStore: referenceStore, competeOnRead: true}
	generator := NewTokenRevocationResponseGenerator(references, storage_impl.NewRefreshTokenStore(), raceLogger())

	response, err := generator.Handle(ctx, raceValidationResult(wicket.TokenTypeHintsAccessToken))
	if err != nil {
		t.Fatalf("revocation losing the race returned error: %v", err)
	}
	if response == nil || !response.Success {
		t.Fatalf("response = %+v, want Success", response)
	}
	if len(references.removeErrs) != 1 || references.removeErrs[0] != nil {
		t.Fatalf("RemoveReferenceToken results = %v, want one nil", references.removeErrs)
	}
	if len(references.batchRemoveErrs) != 0 {
		t.Fatalf("access token revocation ran %d batch removals, want 0", len(references.batchRemoveErrs))
	}
}
