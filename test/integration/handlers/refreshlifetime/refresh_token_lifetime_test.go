// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package refreshlifetime covers, at the token endpoint, the lifetime a
// refresh token is issued with and the client it is bound to: expiry under
// absolute and sliding expiration, survival of a host cleanup right after
// issue, dating of records stored without a creation time, and refusal of a
// refresh token presented by another client.
package refreshlifetime

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	// defaultClient keeps the default lifetime of models.NewClient().
	defaultClient = "lifetime.default"
	// otherClient is a second client with the default lifetime.
	otherClient = "lifetime.other"
	// absoluteClient's refresh tokens expire 10 minutes after issue.
	absoluteClient = "lifetime.absolute"
	// slidingClient's refresh tokens expire 4 minutes after their last
	// redemption, and at the latest 10 minutes after issue.
	slidingClient = "lifetime.sliding"
	secret        = "secret"
)

func client(id string) *storage_models.Client {
	c := storage_models.NewClient()
	c.ClientId = id
	clientSecret := storage_models.NewSecret()
	clientSecret.Value = utils.Sha256(secret)
	c.ClientSecrets = []*storage_models.Secret{clientSecret}
	if err := c.SetAllowedGrantTypes(wicket.GrantTypesPassword); err != nil {
		panic(err)
	}
	c.AllowOfflineAccess = true
	c.AllowedScopes = []string{"api1"}
	c.RefreshTokenUsage = wicket.TokenUsageReUse
	return c
}

func clients() []*storage_models.Client {
	absolute := client(absoluteClient)
	absolute.RefreshTokenExpiration = wicket.TokenExpirationAbsolute
	absolute.AbsoluteRefreshTokenLifetime = 600

	sliding := client(slidingClient)
	sliding.RefreshTokenExpiration = wicket.TokenExpirationSliding
	sliding.SlidingRefreshTokenLifetime = 240
	sliding.AbsoluteRefreshTokenLifetime = 600
	return []*storage_models.Client{client(defaultClient), client(otherClient), absolute, sliding}
}

type fixture struct {
	*integration_common.WicketPipeline
	store storage.RefreshTokenStore
}

// newFixture starts a pipeline whose refresh tokens are kept in store.
func newFixture(t *testing.T, store storage.RefreshTokenStore) *fixture {
	t.Helper()
	pipeline := integration_common.NewWicketPipeline()
	pipeline.Root.ServerConfig().SetRefreshTokenStore(store)
	pipeline.Clients = append(pipeline.Clients, clients()...)

	resource := storage_models.NewApiResource()
	resource.Name = "api1"
	resource.Scopes = []string{"api1"}
	pipeline.ApiResources = append(pipeline.ApiResources, resource)
	scope := storage_models.NewApiScope()
	scope.Name = "api1"
	pipeline.ApiScopes = append(pipeline.ApiScopes, scope)

	user := test.NewTestUser()
	user.SubjectId = "1"
	user.Username = "bob"
	user.Password = "bob"
	pipeline.Users = append(pipeline.Users, user)

	pipeline.Initialize()
	t.Cleanup(pipeline.TestServer.Close)
	return &fixture{WicketPipeline: pipeline, store: store}
}

func (f *fixture) post(t *testing.T, form url.Values) (int, string) {
	t.Helper()
	response, err := f.BackChannelClient.PostForm(f.TestServer.URL+integration_common.TokenEndpoint, form)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response.StatusCode, string(body)
}

// issue runs a password grant for bob and returns the refresh token.
func (f *fixture) issue(t *testing.T, clientId string) string {
	t.Helper()
	status, body := f.post(t, url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientId},
		"client_secret": {secret},
		"scope":         {"api1 offline_access"},
		"username":      {"bob"},
		"password":      {"bob"},
	})
	require.Equal(t, http.StatusOK, status, "token endpoint: %s", body)
	refresh := gjson.Get(body, "refresh_token").String()
	require.NotEmpty(t, refresh)
	return refresh
}

func (f *fixture) exchange(t *testing.T, clientId string, refresh string) (int, string) {
	t.Helper()
	return f.post(t, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientId},
		"client_secret": {secret},
		"refresh_token": {refresh},
	})
}

// redeem exchanges the refresh token and returns the refresh token of the
// response.
func (f *fixture) redeem(t *testing.T, clientId string, refresh string) string {
	t.Helper()
	status, body := f.exchange(t, clientId, refresh)
	require.Equal(t, http.StatusOK, status, "refresh exchange: %s", body)
	next := gjson.Get(body, "refresh_token").String()
	require.NotEmpty(t, next)
	return next
}

// requireRefused asserts invalid_grant and returns the response body.
func (f *fixture) requireRefused(t *testing.T, clientId string, refresh string) string {
	t.Helper()
	status, body := f.exchange(t, clientId, refresh)
	require.Equal(t, http.StatusBadRequest, status, "refresh exchange: %s", body)
	require.Equal(t, "invalid_grant", gjson.Get(body, "error").String())
	return body
}

// agingStore makes the refresh tokens it holds older as the test advances
// its clock. The container gives the refresh token service the system clock
// and offers no seam to replace it, so instead of moving the service's clock
// forward the store moves every creation time it hands out backward by the
// same amount, and forward again when the record is written back: the
// service then sees each record exactly as old as the adjustable clock says.
// The wall clock still runs between requests, by milliseconds, so the
// assertions stay a minute away from every expiry.
type agingStore struct {
	*storage_impl.RefreshTokenStore
	clock *integration_common.AdjustableClock
	start time.Time
}

func newAgingStore(clock *integration_common.AdjustableClock) *agingStore {
	return &agingStore{RefreshTokenStore: storage_impl.NewRefreshTokenStore(), clock: clock, start: clock.Now()}
}

func (s *agingStore) age() time.Duration { return s.clock.Now().Sub(s.start) }

// shifted runs write with the creation time of token moved by d, restoring
// it afterwards; a record without a creation time is left as it is.
func shifted(token *storage_models.RefreshToken, d time.Duration, write func() error) error {
	if token == nil || token.CreationTime.IsZero() {
		return write()
	}
	original := token.CreationTime
	token.CreationTime = original.Add(d)
	defer func() { token.CreationTime = original }()
	return write()
}

func (s *agingStore) StoreRefreshToken(ctx context.Context, handle string, token *storage_models.RefreshToken) error {
	return shifted(token, s.age(), func() error { return s.RefreshTokenStore.StoreRefreshToken(ctx, handle, token) })
}

func (s *agingStore) UpdateRefreshToken(ctx context.Context, handle string, token *storage_models.RefreshToken, expectedVersion int) error {
	return shifted(token, s.age(), func() error {
		return s.RefreshTokenStore.UpdateRefreshToken(ctx, handle, token, expectedVersion)
	})
}

func (s *agingStore) GetRefreshToken(ctx context.Context, handle string) (*storage_models.RefreshToken, error) {
	token, err := s.RefreshTokenStore.GetRefreshToken(ctx, handle)
	if err == nil && !token.CreationTime.IsZero() {
		token.CreationTime = token.CreationTime.Add(-s.age())
	}
	return token, err
}

func newClock() *integration_common.AdjustableClock {
	return integration_common.NewAdjustableClock(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
}

// A refresh token survives RemoveExpired(now) run by the host right after
// issue, under the default client lifetime, and is redeemed after it.
func TestRefreshTokenSurvivesHostCleanup(t *testing.T) {
	store := storage_impl.NewRefreshTokenStore()
	f := newFixture(t, store)
	refresh := f.issue(t, defaultClient)

	removed, err := store.RemoveExpired(context.Background(), godi.GetRequired[services.SystemClock](f.Root).Now())
	require.NoError(t, err)
	require.Zero(t, removed, "RemoveExpired reclaimed a valid refresh token")
	f.redeem(t, defaultClient, refresh)
}

func TestRefreshTokenAbsoluteExpiryAtTheTokenEndpoint(t *testing.T) {
	clock := newClock()
	f := newFixture(t, newAgingStore(clock))
	refresh := f.issue(t, absoluteClient)

	clock.Advance(5 * time.Minute)
	f.redeem(t, absoluteClient, refresh)
	clock.Advance(4 * time.Minute) // 9 min: redemption did not extend the lifetime
	f.redeem(t, absoluteClient, refresh)
	clock.Advance(2 * time.Minute) // 11 min
	f.requireRefused(t, absoluteClient, refresh)
}

func TestRefreshTokenSlidingExpiryAtTheTokenEndpoint(t *testing.T) {
	t.Run("renewed and capped", func(t *testing.T) {
		clock := newClock()
		f := newFixture(t, newAgingStore(clock))
		refresh := f.issue(t, slidingClient)

		clock.Advance(3 * time.Minute) // expires 4 min after this redemption
		f.redeem(t, slidingClient, refresh)
		clock.Advance(3 * time.Minute) // 6 min: past the first 4 min, still valid
		f.redeem(t, slidingClient, refresh)
		clock.Advance(3 * time.Minute) // 9 min: renewed up to the 10 min cap
		f.redeem(t, slidingClient, refresh)
		clock.Advance(2 * time.Minute) // 11 min: past the cap
		f.requireRefused(t, slidingClient, refresh)
	})
	t.Run("window lapses", func(t *testing.T) {
		clock := newClock()
		f := newFixture(t, newAgingStore(clock))
		refresh := f.issue(t, slidingClient)

		clock.Advance(3 * time.Minute)
		f.redeem(t, slidingClient, refresh)
		clock.Advance(6 * time.Minute) // 9 min: more than 4 min since the last redemption
		f.requireRefused(t, slidingClient, refresh)
	})
}

// A record issued before lifetimes were recorded, without a creation time or
// a lifetime, is dated by its first redemption at the token endpoint, and
// the dates reach the store through the update that follows.
func TestRefreshTokenLegacyRecordBackfilledAtTheTokenEndpoint(t *testing.T) {
	f := newFixture(t, storage_impl.NewRefreshTokenStore())
	refresh := f.issue(t, defaultClient)

	token, err := f.store.GetRefreshToken(context.Background(), refresh)
	require.NoError(t, err)
	token.CreationTime = time.Time{}
	token.Lifetime = 0
	require.NoError(t, f.store.UpdateRefreshToken(context.Background(), refresh, token, token.Version))

	require.Equal(t, refresh, f.redeem(t, defaultClient, refresh))
	dated, err := f.store.GetRefreshToken(context.Background(), refresh)
	require.NoError(t, err)
	require.False(t, dated.CreationTime.IsZero(), "the redemption did not write the backfilled creation time back")
	require.Equal(t, 2592000, dated.Lifetime)
}

// A refresh token presented by a client other than the one it was issued to
// is refused as invalid_grant, whether it is valid or expired, with the same
// answer, and the client it was issued to still redeems a valid one.
func TestRefreshTokenBoundToItsClient(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := newFixture(t, storage_impl.NewRefreshTokenStore())
		refresh := f.issue(t, defaultClient)

		f.requireRefused(t, otherClient, refresh)
		f.redeem(t, defaultClient, refresh)
	})
	t.Run("expired", func(t *testing.T) {
		clock := newClock()
		f := newFixture(t, newAgingStore(clock))
		valid := f.issue(t, absoluteClient)
		expired := f.issue(t, absoluteClient)
		validAnswer := f.requireRefused(t, otherClient, valid)

		clock.Advance(11 * time.Minute)
		require.Equal(t, validAnswer, f.requireRefused(t, otherClient, expired),
			"another client learns that the refresh token expired")
		f.requireRefused(t, absoluteClient, expired)
	})
}
