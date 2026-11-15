// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dpop"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/storage/models"
)

type consumptionClock struct{}

func (consumptionClock) Now() time.Time { return consumptionNow }

var consumptionNow = time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)

// rotationStore is the in-memory store with a record of the handles stored
// through it and failures the test can inject.
type rotationStore struct {
	*storage_impl.RefreshTokenStore

	mu        sync.Mutex
	stored    []string
	getFault  map[string]error
	updateErr error
	storeErr  error
	removeErr error
	// appliedUpdateErr, when set, is reported by updates the store applied.
	appliedUpdateErr error
	// beforeUpdate, when set, runs once before the next update reaches the
	// store.
	beforeUpdate func(handle string)
}

func (s *rotationStore) setFault(set func(*rotationStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set(s)
}

func newRotationStore() *rotationStore {
	return &rotationStore{RefreshTokenStore: storage_impl.NewRefreshTokenStore(), getFault: map[string]error{}}
}

func (s *rotationStore) StoreRefreshToken(ctx context.Context, handle string, token *models.RefreshToken) error {
	s.mu.Lock()
	err := s.storeErr
	if err == nil {
		s.stored = append(s.stored, handle)
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.RefreshTokenStore.StoreRefreshToken(ctx, handle, token)
}

func (s *rotationStore) GetRefreshToken(ctx context.Context, handle string) (*models.RefreshToken, error) {
	s.mu.Lock()
	err := s.getFault[handle]
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.RefreshTokenStore.GetRefreshToken(ctx, handle)
}

func (s *rotationStore) UpdateRefreshToken(ctx context.Context, handle string, token *models.RefreshToken, expectedVersion int) error {
	s.mu.Lock()
	err := s.updateErr
	applied := s.appliedUpdateErr
	hook := s.beforeUpdate
	s.beforeUpdate = nil
	s.mu.Unlock()
	if hook != nil {
		hook(handle)
	}
	if err != nil {
		return err
	}
	if err := s.RefreshTokenStore.UpdateRefreshToken(ctx, handle, token, expectedVersion); err != nil {
		return err
	}
	return applied
}

func (s *rotationStore) RemoveRefreshToken(ctx context.Context, handle string) error {
	s.mu.Lock()
	err := s.removeErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.RefreshTokenStore.RemoveRefreshToken(ctx, handle)
}

func (s *rotationStore) storedHandles() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.stored...)
}

func consumptionClient(id string, usage wicket.TokenUsage) *models.Client {
	client := models.NewClient()
	client.ClientId = id
	client.RefreshTokenUsage = usage
	return client
}

func consumptionService(store storage.RefreshTokenStore, consumption services.RefreshTokenConsumption) *RefreshTokenService {
	service := NewRefreshTokenService(store, NewHandleGenerationService())
	service.SetConsumption(consumption, consumptionClock{}, nil)
	return service
}

// issueRefreshToken stores a refresh token for client under handle.
func issueRefreshToken(t *testing.T, store storage.RefreshTokenStore, handle string, client *models.Client) {
	t.Helper()
	token := models.NewRefreshToken()
	token.ClientId = client.ClientId
	token.SessionId = "session-1"
	token.CreationTime = consumptionNow.Add(-time.Hour)
	token.Lifetime = 86400
	token.AuthorizedScopes = []string{"openid", "api"}
	token.AuthorizedResourceGaps = []string{"https://api.example"}
	token.DPoPKeyThumbprint = "jkt-1"
	token.SetAccessToken(&models.Token{ClientId: client.ClientId, Lifetime: 300}, "")
	if err := store.StoreRefreshToken(context.Background(), handle, token); err != nil {
		t.Fatalf("store %s: %v", handle, err)
	}
}

const (
	outcomeIssued       = "issued"
	outcomeInvalidGrant = "invalid_grant"
	outcomeServerError  = "server_error"
)

// holderContext carries a proof of the key issueRefreshToken binds tokens to,
// as a request of the legitimate holder does.
var holderContext = dpop.WithProof(context.Background(), "jkt-1")

// redeem validates and updates the refresh token as the token endpoint
// does for the legitimate holder, and classifies the outcome as the endpoint
// would answer it.
func redeem(t *testing.T, service *RefreshTokenService, handle string, client *models.Client) (string, string, error) {
	t.Helper()
	return redeemIn(t, holderContext, service, handle, client)
}

func redeemIn(t *testing.T, ctx context.Context, service *RefreshTokenService, handle string, client *models.Client) (string, string, error) {
	t.Helper()
	result := service.ValidateRefreshToken(ctx, handle, client)
	if result.Error != nil {
		if errors.Is(result.Error, storage.ErrNotFound) {
			return "", outcomeInvalidGrant, result.Error
		}
		return "", outcomeServerError, result.Error
	}
	next, err := service.UpdateRefreshToken(ctx, &responses_models.RefreshTokenUpdateRequest{
		Handle:       handle,
		Client:       client,
		RefreshToken: result.RefreshToken,
		AccessToken:  &models.Token{ClientId: client.ClientId, Lifetime: 600},
	})
	if err != nil {
		if errors.Is(err, storage.ErrVersionConflict) {
			return "", outcomeInvalidGrant, err
		}
		return "", outcomeServerError, err
	}
	return next, outcomeIssued, nil
}

func requireIssued(t *testing.T, service *RefreshTokenService, handle string, client *models.Client) string {
	t.Helper()
	next, outcome, err := redeem(t, service, handle, client)
	if outcome != outcomeIssued {
		t.Fatalf("redeem: outcome %s (%v), want %s", outcome, err, outcomeIssued)
	}
	return next
}

func requireRefused(t *testing.T, service *RefreshTokenService, handle string, client *models.Client) {
	t.Helper()
	if _, outcome, err := redeem(t, service, handle, client); outcome != outcomeInvalidGrant {
		t.Fatalf("redeem: outcome %s (%v), want %s", outcome, err, outcomeInvalidGrant)
	}
}

func getRefreshToken(t *testing.T, store storage.RefreshTokenStore, handle string) *models.RefreshToken {
	t.Helper()
	token, err := store.GetRefreshToken(context.Background(), handle)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return token
}

// Matrix #1 and #7: the handle is kept, and a client reusing its refresh
// tokens keeps it under every consumption.
func TestRefreshTokenConsumptionKeepsTheHandle(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		consumption services.RefreshTokenConsumption
		usage       wicket.TokenUsage
		configured  bool
	}{
		"unconfigured one-time":     {usage: wicket.TokenUsageOneTimeOnly},
		"kept one-time":             {consumption: services.RefreshTokenKeptOnRedemption, usage: wicket.TokenUsageOneTimeOnly, configured: true},
		"kept reuse":                {consumption: services.RefreshTokenKeptOnRedemption, usage: wicket.TokenUsageReUse, configured: true},
		"removed reuse":             {consumption: services.RefreshTokenRemovedOnRedemption, usage: wicket.TokenUsageReUse, configured: true},
		"marked reuse":              {consumption: services.RefreshTokenMarkedOnRedemption, usage: wicket.TokenUsageReUse, configured: true},
		"unconfigured reuse client": {usage: wicket.TokenUsageReUse},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newRotationStore()
			client := consumptionClient("client-a", tc.usage)
			issueRefreshToken(t, store, "R", client)
			service := NewRefreshTokenService(store, NewHandleGenerationService())
			if tc.configured {
				service.SetConsumption(tc.consumption, consumptionClock{}, nil)
			}
			for i := range 3 {
				if next := requireIssued(t, service, "R", client); next != "R" {
					t.Fatalf("redemption %d returned %q, want the same handle", i, next)
				}
			}
			token := getRefreshToken(t, store, "R")
			if token.ConsumedTime != nil || token.RotatedTo != "" {
				t.Fatalf("kept token marked: consumed %v, rotated to %q", token.ConsumedTime, token.RotatedTo)
			}
			if got := store.storedHandles(); !reflect.DeepEqual(got, []string{"R"}) {
				t.Fatalf("stored handles %v, want only the issued one", got)
			}
		})
	}
}

// Matrix #2 and #3.
func TestRefreshTokenConsumptionRemoved(t *testing.T) {
	t.Parallel()
	store := newRotationStore()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	issueRefreshToken(t, store, "R", client)
	service := consumptionService(store, services.RefreshTokenRemovedOnRedemption)

	r1 := requireIssued(t, service, "R", client)
	if r1 == "R" || r1 == "" {
		t.Fatalf("rotation returned %q, want a new handle", r1)
	}
	if _, err := store.GetRefreshToken(context.Background(), "R"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("redeemed record still present: %v", err)
	}
	requireRefused(t, service, "R", client)
	r2 := requireIssued(t, service, r1, client)
	if r2 == r1 {
		t.Fatal("second rotation kept the handle")
	}
}

// Matrix #4 and #12: the redeemed record stays, marked and linked, and the
// successor inherits everything the redeemed token authorizes.
func TestRefreshTokenConsumptionMarkedRecordAndSuccessor(t *testing.T) {
	t.Parallel()
	for name, consumption := range map[string]services.RefreshTokenConsumption{
		"removed": services.RefreshTokenRemovedOnRedemption,
		"marked":  services.RefreshTokenMarkedOnRedemption,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newRotationStore()
			client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
			issueRefreshToken(t, store, "R", client)
			original := getRefreshToken(t, store, "R")
			service := consumptionService(store, consumption)

			r1 := requireIssued(t, service, "R", client)

			successor := getRefreshToken(t, store, r1)
			if successor.ConsumedTime != nil || successor.RotatedTo != "" {
				t.Fatalf("successor marked: consumed %v, rotated to %q", successor.ConsumedTime, successor.RotatedTo)
			}
			if successor.Version != 1 {
				t.Fatalf("successor version %d, want the store's first version", successor.Version)
			}
			if successor.ClientId != original.ClientId ||
				successor.SessionId != original.SessionId ||
				!successor.CreationTime.Equal(original.CreationTime) ||
				successor.Lifetime != original.Lifetime ||
				successor.DPoPKeyThumbprint != "jkt-1" ||
				!reflect.DeepEqual(successor.AuthorizedScopes, original.AuthorizedScopes) ||
				!reflect.DeepEqual(successor.AuthorizedResourceGaps, original.AuthorizedResourceGaps) {
				t.Fatalf("successor %+v does not inherit %+v", successor, original)
			}
			if got := successor.GetAccessToken(""); got == nil || got.Lifetime != 600 {
				t.Fatalf("successor access token %+v, want the one issued by this redemption", got)
			}

			if consumption != services.RefreshTokenMarkedOnRedemption {
				return
			}
			redeemed := getRefreshToken(t, store, "R")
			if redeemed.ConsumedTime == nil || !redeemed.ConsumedTime.Equal(consumptionNow) {
				t.Fatalf("redeemed consumed time %v, want %v", redeemed.ConsumedTime, consumptionNow)
			}
			if redeemed.RotatedTo != r1 {
				t.Fatalf("redeemed rotated to %q, want %q", redeemed.RotatedTo, r1)
			}
		})
	}
}

// Matrix #5, #6 and #10.
func TestRefreshTokenConsumptionMarkedReplay(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)

	t.Run("replay by the client revokes the valid successor", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		issueRefreshToken(t, store, "S", client)
		service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
		r1 := requireIssued(t, service, "R", client)
		r2 := requireIssued(t, service, r1, client)
		s1 := requireIssued(t, service, "S", client)

		requireRefused(t, service, "R", client)

		revoked := getRefreshToken(t, store, r2)
		if revoked.ConsumedTime == nil || revoked.RotatedTo != "" {
			t.Fatalf("successor after replay: consumed %v, rotated to %q; want revoked", revoked.ConsumedTime, revoked.RotatedTo)
		}
		requireRefused(t, service, r2, client)
		// The other chain is untouched.
		requireIssued(t, service, s1, client)
	})

	t.Run("another client presenting it revokes nothing", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
		r1 := requireIssued(t, service, "R", client)

		requireRefused(t, service, "R", consumptionClient("client-b", wicket.TokenUsageOneTimeOnly))
		requireRefused(t, service, "R", nil)

		requireIssued(t, service, r1, client)
	})

	t.Run("a store failure during revocation is not invalid_grant", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
		r1 := requireIssued(t, service, "R", client)
		boom := errors.New("store unavailable")

		store.mu.Lock()
		store.getFault[r1] = boom
		store.mu.Unlock()
		_, outcome, err := redeem(t, service, "R", client)
		if outcome != outcomeServerError || !errors.Is(err, boom) {
			t.Fatalf("read failure: outcome %s (%v), want %s wrapping the store error", outcome, err, outcomeServerError)
		}

		store.mu.Lock()
		delete(store.getFault, r1)
		store.updateErr = boom
		store.mu.Unlock()
		_, outcome, err = redeem(t, service, "R", client)
		if outcome != outcomeServerError || !errors.Is(err, boom) {
			t.Fatalf("write failure: outcome %s (%v), want %s wrapping the store error", outcome, err, outcomeServerError)
		}
	})
}

// Matrix #9: a consumed record is refused whatever the consumption.
func TestRefreshTokenConsumptionConsumedRefusedAfterSwitchingBack(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	store := newRotationStore()
	issueRefreshToken(t, store, "R", client)
	r1 := requireIssued(t, consumptionService(store, services.RefreshTokenMarkedOnRedemption), "R", client)

	unconfigured := NewRefreshTokenService(store, NewHandleGenerationService())
	requireRefused(t, unconfigured, "R", client)
	// Without a clock nothing is revoked.
	requireIssued(t, unconfigured, r1, client)

	kept := consumptionService(store, services.RefreshTokenKeptOnRedemption)
	requireRefused(t, kept, "R", client)
	requireRefused(t, kept, r1, client)
}

// Matrix #8: of concurrent redemptions of one handle exactly one succeeds,
// and every loser removes the successor it stored.
func TestRefreshTokenConsumptionConcurrentRedemption(t *testing.T) {
	t.Parallel()
	const redemptions = 16
	for name, consumption := range map[string]services.RefreshTokenConsumption{
		"removed": services.RefreshTokenRemovedOnRedemption,
		"marked":  services.RefreshTokenMarkedOnRedemption,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newRotationStore()
			client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
			issueRefreshToken(t, store, "R", client)
			service := consumptionService(store, consumption)

			// Every redemption reads the record before any of them writes,
			// as concurrent requests passing validation together do.
			start := make(chan struct{})
			var wg sync.WaitGroup
			handles := make([]string, redemptions)
			errs := make([]error, redemptions)
			for i := range redemptions {
				result := service.ValidateRefreshToken(context.Background(), "R", client)
				if result.Error != nil {
					t.Fatalf("validate: %v", result.Error)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					handles[i], errs[i] = service.UpdateRefreshToken(context.Background(), &responses_models.RefreshTokenUpdateRequest{
						Handle:       "R",
						Client:       client,
						RefreshToken: result.RefreshToken,
						AccessToken:  &models.Token{ClientId: client.ClientId},
					})
				}()
			}
			close(start)
			wg.Wait()

			winner := ""
			for i, err := range errs {
				switch {
				case err == nil:
					if winner != "" {
						t.Fatalf("two redemptions succeeded: %q and %q", winner, handles[i])
					}
					winner = handles[i]
				case !errors.Is(err, storage.ErrVersionConflict):
					t.Fatalf("losing redemption error %v, want ErrVersionConflict", err)
				}
			}
			if winner == "" || winner == "R" {
				t.Fatalf("winning handle %q, want a new one", winner)
			}
			for _, handle := range store.storedHandles() {
				_, err := store.RefreshTokenStore.GetRefreshToken(context.Background(), handle)
				switch handle {
				case winner:
					if err != nil {
						t.Fatalf("winning successor missing: %v", err)
					}
				case "R":
				default:
					if !errors.Is(err, storage.ErrNotFound) {
						t.Fatalf("losing successor left behind: %v", err)
					}
				}
			}
			requireIssued(t, service, winner, client)
		})
	}
}

// A redemption that finds the redeemed record already removed by a
// concurrent redemption under the removing consumption loses like one that
// finds it updated.
func TestRefreshTokenConsumptionRedeemedRecordRemovedMeanwhile(t *testing.T) {
	t.Parallel()
	store := newRotationStore()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	issueRefreshToken(t, store, "R", client)
	service := consumptionService(store, services.RefreshTokenRemovedOnRedemption)

	validated := service.ValidateRefreshToken(context.Background(), "R", client)
	if validated.Error != nil {
		t.Fatalf("validate: %v", validated.Error)
	}
	if err := store.RemoveRefreshToken(context.Background(), "R"); err != nil {
		t.Fatal(err)
	}
	_, err := service.UpdateRefreshToken(context.Background(), &responses_models.RefreshTokenUpdateRequest{
		Handle:       "R",
		Client:       client,
		RefreshToken: validated.RefreshToken,
	})
	if !errors.Is(err, storage.ErrVersionConflict) {
		t.Fatalf("update error %v, want ErrVersionConflict", err)
	}
	for _, handle := range store.storedHandles()[1:] {
		if _, err := store.GetRefreshToken(context.Background(), handle); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("successor left behind: %v", err)
		}
	}
	if len(store.storedHandles()) != 2 {
		t.Fatalf("stored handles %v, want the issued one and one successor", store.storedHandles())
	}
}

// A failed write leaves the redeemed token as it was.
func TestRefreshTokenConsumptionStoreFailures(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	boom := errors.New("store unavailable")

	t.Run("storing the successor", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
		store.setFault(func(s *rotationStore) { s.storeErr = boom })
		_, outcome, err := redeem(t, service, "R", client)
		if outcome != outcomeServerError || !errors.Is(err, boom) {
			t.Fatalf("outcome %s (%v), want %s", outcome, err, outcomeServerError)
		}
		store.setFault(func(s *rotationStore) { s.storeErr = nil })
		if token := getRefreshToken(t, store, "R"); token.ConsumedTime != nil || token.Version != 1 {
			t.Fatalf("redeemed token changed: %+v", token)
		}
		requireIssued(t, service, "R", client)
	})

	t.Run("consuming the redeemed token", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		service := consumptionService(store, services.RefreshTokenRemovedOnRedemption)
		store.setFault(func(s *rotationStore) { s.updateErr = boom })
		_, outcome, err := redeem(t, service, "R", client)
		if outcome != outcomeServerError || !errors.Is(err, boom) {
			t.Fatalf("outcome %s (%v), want %s", outcome, err, outcomeServerError)
		}
		store.setFault(func(s *rotationStore) { s.updateErr = nil })
		for _, handle := range store.storedHandles()[1:] {
			if _, err := store.GetRefreshToken(context.Background(), handle); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("successor left behind: %v", err)
			}
		}
		requireIssued(t, service, "R", client)
	})
}

// The revocation walk ends without error on a cycle a faulty store could
// hold in the rotation links (missing case d), whether or not the presented
// token is on it.
func TestRefreshTokenConsumptionRevocationWalkCycle(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	for name, links := range map[string]map[string]string{
		"through the presented token": {"A": "B", "B": "A"},
		"past the presented token":    {"A": "B", "B": "C", "C": "B"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newRotationStore()
			consumed := consumptionNow
			for handle, next := range links {
				token := models.NewRefreshToken()
				token.ClientId = client.ClientId
				token.ConsumedTime = &consumed
				token.RotatedTo = next
				if err := store.StoreRefreshToken(context.Background(), handle, token); err != nil {
					t.Fatal(err)
				}
			}
			service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
			requireRefused(t, service, "A", client)
		})
	}
}

// A walk losing its write to a redemption of the same token re-reads it and
// revokes the token issued by that redemption (missing case a).
func TestRefreshTokenConsumptionRevocationWalkLosesARace(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	store := newRotationStore()
	issueRefreshToken(t, store, "R", client)
	service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
	r1 := requireIssued(t, service, "R", client)

	var r2 string
	store.setFault(func(s *rotationStore) {
		s.beforeUpdate = func(handle string) {
			if handle != r1 {
				t.Errorf("walk updated %q first, want the valid successor", handle)
			}
			r2 = requireIssued(t, service, r1, client)
		}
	})
	requireRefused(t, service, "R", client)

	if r2 == "" {
		t.Fatal("the racing redemption did not run")
	}
	revoked := getRefreshToken(t, store, r2)
	if revoked.ConsumedTime == nil || revoked.RotatedTo != "" {
		t.Fatalf("newest successor: consumed %v, rotated to %q; want revoked", revoked.ConsumedTime, revoked.RotatedTo)
	}
	requireRefused(t, service, r2, client)
}

// A store that keeps reporting conflicts during the walk ends in a server
// error, never in invalid_grant with nothing revoked (missing case c).
func TestRefreshTokenConsumptionRevocationWalkPersistentConflicts(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	store := newRotationStore()
	issueRefreshToken(t, store, "R", client)
	service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
	requireIssued(t, service, "R", client)

	store.setFault(func(s *rotationStore) { s.updateErr = storage.ErrVersionConflict })
	_, outcome, err := redeem(t, service, "R", client)
	if outcome != outcomeServerError || err == nil || errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("outcome %s (%v), want %s not wrapping ErrNotFound", outcome, err, outcomeServerError)
	}
}

// A failed removal is only logged (missing case b).
func TestRefreshTokenConsumptionRemovalFailures(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	boom := errors.New("store unavailable")

	t.Run("the redeemed record stays consumed and is refused", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		service := consumptionService(store, services.RefreshTokenRemovedOnRedemption)
		store.setFault(func(s *rotationStore) { s.removeErr = boom })

		r1 := requireIssued(t, service, "R", client)
		if r1 == "R" {
			t.Fatal("rotation kept the handle")
		}
		if leftover := getRefreshToken(t, store, "R"); leftover.ConsumedTime == nil {
			t.Fatal("leftover record not marked as consumed")
		}
		requireRefused(t, service, "R", client)
		requireIssued(t, service, r1, client)
	})

	t.Run("a losing redemption still conflicts", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		service := consumptionService(store, services.RefreshTokenRemovedOnRedemption)
		first := service.ValidateRefreshToken(holderContext, "R", client)
		second := service.ValidateRefreshToken(holderContext, "R", client)
		if first.Error != nil || second.Error != nil {
			t.Fatalf("validate: %v / %v", first.Error, second.Error)
		}
		store.setFault(func(s *rotationStore) { s.removeErr = boom })
		update := func(token *models.RefreshToken) (string, error) {
			return service.UpdateRefreshToken(holderContext, &responses_models.RefreshTokenUpdateRequest{
				Handle: "R", Client: client, RefreshToken: token,
			})
		}
		if _, err := update(first.RefreshToken); err != nil {
			t.Fatalf("winning redemption: %v", err)
		}
		if _, err := update(second.RefreshToken); !errors.Is(err, storage.ErrVersionConflict) {
			t.Fatalf("losing redemption error %v, want ErrVersionConflict", err)
		}
	})
}

// A consumed token bound to a DPoP key revokes its successors only when
// presented with a proof of that key; an unbound one revokes without.
func TestRefreshTokenConsumptionReplayOfABoundToken(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	cases := map[string]struct {
		binding string
		ctx     context.Context
		revokes bool
	}{
		"bound, no proof":         {binding: "jkt-1", ctx: context.Background()},
		"bound, another key":      {binding: "jkt-1", ctx: dpop.WithProof(context.Background(), "jkt-2")},
		"bound, the key":          {binding: "jkt-1", ctx: dpop.WithProof(context.Background(), "jkt-1"), revokes: true},
		"unbound, no proof":       {ctx: context.Background(), revokes: true},
		"unbound, with any proof": {ctx: dpop.WithProof(context.Background(), "jkt-2"), revokes: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newRotationStore()
			token := models.NewRefreshToken()
			token.ClientId = client.ClientId
			token.CreationTime = consumptionNow
			token.Lifetime = 3600
			token.DPoPKeyThumbprint = tc.binding
			if err := store.StoreRefreshToken(context.Background(), "R", token); err != nil {
				t.Fatal(err)
			}
			service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
			holder := dpop.WithProof(context.Background(), tc.binding)
			r1, outcome, err := redeemIn(t, holder, service, "R", client)
			if outcome != outcomeIssued {
				t.Fatalf("redeem: %s (%v)", outcome, err)
			}

			if _, outcome, err := redeemIn(t, tc.ctx, service, "R", client); outcome != outcomeInvalidGrant {
				t.Fatalf("replay: %s (%v), want %s", outcome, err, outcomeInvalidGrant)
			}
			if revoked := getRefreshToken(t, store, r1).ConsumedTime != nil; revoked != tc.revokes {
				t.Fatalf("successor revoked %v, want %v", revoked, tc.revokes)
			}
		})
	}
}

func TestRefreshTokenConsumptionSetterRefusesUndeclaredValues(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*RefreshTokenService){
		"undeclared value": func(s *RefreshTokenService) {
			s.SetConsumption(services.RefreshTokenConsumption(7), consumptionClock{}, nil)
		},
		"nil clock": func(s *RefreshTokenService) {
			s.SetConsumption(services.RefreshTokenMarkedOnRedemption, nil, nil)
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				recovered := recover()
				if recovered == nil || !strings.Contains(recovered.(string), "refresh token consumption") {
					t.Fatalf("panic %v, want one naming the consumption", recovered)
				}
			}()
			call(NewRefreshTokenService(newRotationStore(), NewHandleGenerationService()))
		})
	}
}

// A store reporting a failure for a consumption it applied answers the
// successor under the marking consumption, since the redeemed token already
// links to it; under the removing one the write cannot be attributed, and
// the redemption fails as before.
func TestRefreshTokenConsumptionUpdateAppliedDespiteFailure(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	boom := errors.New("store timed out")

	t.Run("marked", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
		store.setFault(func(s *rotationStore) { s.appliedUpdateErr = boom })
		r1, outcome, err := redeem(t, service, "R", client)
		store.setFault(func(s *rotationStore) { s.appliedUpdateErr = nil })
		if outcome != outcomeIssued {
			t.Fatalf("outcome %s (%v), want %s", outcome, err, outcomeIssued)
		}
		if consumed := getRefreshToken(t, store, "R"); consumed.ConsumedTime == nil || consumed.RotatedTo != r1 {
			t.Fatalf("redeemed record: consumed %v, rotated to %q; want consumed into %q", consumed.ConsumedTime, consumed.RotatedTo, r1)
		}
		requireIssued(t, service, r1, client)
	})

	t.Run("removed", func(t *testing.T) {
		t.Parallel()
		store := newRotationStore()
		issueRefreshToken(t, store, "R", client)
		service := consumptionService(store, services.RefreshTokenRemovedOnRedemption)
		store.setFault(func(s *rotationStore) { s.appliedUpdateErr = boom })
		_, outcome, err := redeem(t, service, "R", client)
		store.setFault(func(s *rotationStore) { s.appliedUpdateErr = nil })
		if outcome != outcomeServerError || !errors.Is(err, boom) {
			t.Fatalf("outcome %s (%v), want %s wrapping the store error", outcome, err, outcomeServerError)
		}
		for _, handle := range store.storedHandles()[1:] {
			if _, err := store.GetRefreshToken(context.Background(), handle); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("successor left behind: %v", err)
			}
		}
	})
}

// Once a replay has revoked the chain, the replayed token no longer links to
// it: presenting it again is refused without reading the chain.
func TestRefreshTokenConsumptionReplayIsWalkedOnce(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	store := newRotationStore()
	issueRefreshToken(t, store, "R", client)
	service := consumptionService(store, services.RefreshTokenMarkedOnRedemption)
	r1 := requireIssued(t, service, "R", client)
	r2 := requireIssued(t, service, r1, client)

	requireRefused(t, service, "R", client)
	if replayed := getRefreshToken(t, store, "R"); replayed.ConsumedTime == nil || replayed.RotatedTo != "" {
		t.Fatalf("replayed record: consumed %v, rotated to %q; want consumed and unlinked", replayed.ConsumedTime, replayed.RotatedTo)
	}

	// A walk would now fail on these reads and answer a server error.
	boom := errors.New("store unavailable")
	store.setFault(func(s *rotationStore) {
		s.getFault[r1] = boom
		s.getFault[r2] = boom
	})
	requireRefused(t, service, "R", client)
}

// The warnings name the client and session, never a handle.
func TestRefreshTokenConsumptionWarnings(t *testing.T) {
	t.Parallel()
	client := consumptionClient("client-a", wicket.TokenUsageOneTimeOnly)
	const redeemed = "handle-redeemed-0123456789"
	logged := func(t *testing.T, consumption services.RefreshTokenConsumption) (*rotationStore, *RefreshTokenService, *bytes.Buffer) {
		t.Helper()
		var buffer bytes.Buffer
		store := newRotationStore()
		issueRefreshToken(t, store, redeemed, client)
		service := NewRefreshTokenService(store, NewHandleGenerationService())
		service.SetConsumption(consumption, consumptionClock{}, slog.New(slog.NewTextHandler(&buffer, nil)))
		return store, service, &buffer
	}
	requireNoHandle := func(t *testing.T, output string, handles ...string) {
		t.Helper()
		for _, handle := range handles {
			if strings.Contains(output, handle) {
				t.Fatalf("log names handle %q:\n%s", handle, output)
			}
		}
	}

	t.Run("replay", func(t *testing.T) {
		t.Parallel()
		_, service, buffer := logged(t, services.RefreshTokenMarkedOnRedemption)
		r1 := requireIssued(t, service, redeemed, client)
		r2 := requireIssued(t, service, r1, client)
		if buffer.Len() != 0 {
			t.Fatalf("redemptions logged:\n%s", buffer)
		}

		requireRefused(t, service, redeemed, client)
		requireRefused(t, service, redeemed, client)
		output := buffer.String()
		if lines := strings.Count(output, "\n"); lines != 1 {
			t.Fatalf("%d records, want one warning for the revocation:\n%s", lines, output)
		}
		for _, want := range []string{"level=WARN", "presented again", "clientId=client-a", "sessionId=session-1"} {
			if !strings.Contains(output, want) {
				t.Fatalf("warning lacks %q:\n%s", want, output)
			}
		}
		requireNoHandle(t, output, redeemed, r1, r2)
	})

	t.Run("failed removal", func(t *testing.T) {
		t.Parallel()
		store, service, buffer := logged(t, services.RefreshTokenRemovedOnRedemption)
		store.setFault(func(s *rotationStore) { s.removeErr = errors.New("store unavailable") })
		r1 := requireIssued(t, service, redeemed, client)
		output := buffer.String()
		if strings.Count(output, "\n") != 1 || !strings.Contains(output, "level=WARN") || !strings.Contains(output, "token=redeemed") {
			t.Fatalf("want one warning for the redeemed record:\n%s", output)
		}
		requireNoHandle(t, output, redeemed, r1)
	})
}
