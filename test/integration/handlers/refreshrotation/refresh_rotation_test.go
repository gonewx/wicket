// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package refreshrotation covers what the token endpoint does with a redeemed
// one-time refresh token under each declared refresh token consumption. The
// proof key binding a rotated token inherits is covered next to the DPoP
// scene, in test/integration/handlers/dpop/refresh_rotation_test.go.
package refreshrotation

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

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
	// oneTimeClient redeems each refresh token once.
	oneTimeClient = "rotation.onetime"
	// otherOneTimeClient is a second client with one-time refresh tokens.
	otherOneTimeClient = "rotation.onetime.other"
	// reuseClient reuses its refresh tokens.
	reuseClient = "rotation.reuse"
	secret      = "secret"
)

func client(id string, usage wicket.TokenUsage) *storage_models.Client {
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
	c.RefreshTokenUsage = usage
	return c
}

type fixture struct {
	*integration_common.WicketPipeline
	store *storage_impl.RefreshTokenStore
}

// newFixture starts a pipeline over store; a nil consumption leaves the
// declaration out.
func newFixture(t *testing.T, store *storage_impl.RefreshTokenStore, consumption *services.RefreshTokenConsumption) *fixture {
	t.Helper()
	pipeline := integration_common.NewWicketPipeline()
	cfg := pipeline.Root.ServerConfig()
	cfg.SetRefreshTokenStore(store)
	if consumption != nil {
		cfg.SetRefreshTokenConsumption(*consumption)
	}
	pipeline.Clients = append(pipeline.Clients,
		client(oneTimeClient, wicket.TokenUsageOneTimeOnly),
		client(otherOneTimeClient, wicket.TokenUsageOneTimeOnly),
		client(reuseClient, wicket.TokenUsageReUse),
	)

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

func (f *fixture) requireRefused(t *testing.T, clientId string, refresh string) {
	t.Helper()
	status, body := f.exchange(t, clientId, refresh)
	require.Equal(t, http.StatusBadRequest, status, "refresh exchange: %s", body)
	require.Equal(t, "invalid_grant", gjson.Get(body, "error").String())
}

// Matrix #1 and #7: without a declaration, and for a client reusing its
// refresh tokens under every declaration, the handle is kept.
func TestRefreshTokenHandleIsKept(t *testing.T) {
	cases := map[string]struct {
		consumption *services.RefreshTokenConsumption
		clientId    string
	}{
		"undeclared one-time": {clientId: oneTimeClient},
		"undeclared reuse":    {clientId: reuseClient},
		"kept one-time":       {consumption: new(services.RefreshTokenKeptOnRedemption), clientId: oneTimeClient},
		"removed reuse":       {consumption: new(services.RefreshTokenRemovedOnRedemption), clientId: reuseClient},
		"marked reuse":        {consumption: new(services.RefreshTokenMarkedOnRedemption), clientId: reuseClient},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, storage_impl.NewRefreshTokenStore(), tc.consumption)
			refresh := f.issue(t, tc.clientId)
			require.Equal(t, refresh, f.redeem(t, tc.clientId, refresh))
			require.Equal(t, refresh, f.redeem(t, tc.clientId, refresh))
		})
	}
}

// Matrix #2 and #3.
func TestRemovedOnRedemption(t *testing.T) {
	f := newFixture(t, storage_impl.NewRefreshTokenStore(), new(services.RefreshTokenRemovedOnRedemption))
	refresh := f.issue(t, oneTimeClient)

	rotated := f.redeem(t, oneTimeClient, refresh)
	require.NotEqual(t, refresh, rotated)
	_, err := f.store.GetRefreshToken(context.Background(), refresh)
	require.ErrorIs(t, err, storage.ErrNotFound, "the redeemed record is removed")

	f.requireRefused(t, oneTimeClient, refresh)
	// Nothing links the replayed token to its successor.
	require.NotEqual(t, rotated, f.redeem(t, oneTimeClient, rotated))
}

// Matrix #4, #5 and #10.
func TestMarkedOnRedemption(t *testing.T) {
	f := newFixture(t, storage_impl.NewRefreshTokenStore(), new(services.RefreshTokenMarkedOnRedemption))
	refresh := f.issue(t, oneTimeClient)
	other := f.issue(t, oneTimeClient)

	first := f.redeem(t, oneTimeClient, refresh)
	require.NotEqual(t, refresh, first)
	redeemed, err := f.store.GetRefreshToken(context.Background(), refresh)
	require.NoError(t, err)
	require.NotNil(t, redeemed.ConsumedTime)
	require.Equal(t, first, redeemed.RotatedTo)

	second := f.redeem(t, oneTimeClient, first)
	otherRotated := f.redeem(t, oneTimeClient, other)

	// The replay is refused and revokes the token still valid down its link.
	f.requireRefused(t, oneTimeClient, refresh)
	f.requireRefused(t, oneTimeClient, second)
	// Another token family of the same client is untouched.
	f.redeem(t, oneTimeClient, otherRotated)
}

// Matrix #6.
func TestConsumedTokenPresentedByAnotherClient(t *testing.T) {
	f := newFixture(t, storage_impl.NewRefreshTokenStore(), new(services.RefreshTokenMarkedOnRedemption))
	refresh := f.issue(t, oneTimeClient)
	rotated := f.redeem(t, oneTimeClient, refresh)

	f.requireRefused(t, otherOneTimeClient, refresh)
	f.redeem(t, oneTimeClient, rotated)
}

// Matrix #9: a record consumed under the marked declaration is refused once
// the host restarts without a declaration.
func TestConsumedTokenRefusedAfterSwitchingBack(t *testing.T) {
	store := storage_impl.NewRefreshTokenStore()
	marked := newFixture(t, store, new(services.RefreshTokenMarkedOnRedemption))
	refresh := marked.issue(t, oneTimeClient)
	rotated := marked.redeem(t, oneTimeClient, refresh)
	marked.TestServer.Close()

	restarted := newFixture(t, store, nil)
	restarted.requireRefused(t, oneTimeClient, refresh)
	// The replay revoked the successor, which was still valid.
	restarted.requireRefused(t, oneTimeClient, rotated)
}

// Matrix #8 at the endpoint: of simultaneous redemptions of one handle
// exactly one is answered with a new handle, all others with invalid_grant.
func TestConcurrentRedemption(t *testing.T) {
	const requests = 12
	for name, consumption := range map[string]services.RefreshTokenConsumption{
		"removed": services.RefreshTokenRemovedOnRedemption,
		"marked":  services.RefreshTokenMarkedOnRedemption,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, storage_impl.NewRefreshTokenStore(), &consumption)
			refresh := f.issue(t, oneTimeClient)

			type answer struct {
				status int
				body   string
			}
			answers := make([]answer, requests)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range requests {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					form := url.Values{
						"grant_type":    {"refresh_token"},
						"client_id":     {oneTimeClient},
						"client_secret": {secret},
						"refresh_token": {refresh},
					}
					response, err := f.BackChannelClient.PostForm(f.TestServer.URL+integration_common.TokenEndpoint, form)
					if err != nil {
						answers[i] = answer{body: err.Error()}
						return
					}
					body, _ := io.ReadAll(response.Body)
					_ = response.Body.Close()
					answers[i] = answer{status: response.StatusCode, body: string(body)}
				}()
			}
			close(start)
			wg.Wait()

			issued := 0
			for _, a := range answers {
				switch a.status {
				case http.StatusOK:
					issued++
					next := gjson.Get(a.body, "refresh_token").String()
					require.NotEmpty(t, next)
					require.NotEqual(t, refresh, next)
				case http.StatusBadRequest:
					require.Equal(t, "invalid_grant", gjson.Get(a.body, "error").String(), a.body)
				default:
					t.Fatalf("unexpected answer %d: %s", a.status, a.body)
				}
			}
			require.Equal(t, 1, issued, "exactly one redemption succeeds")
		})
	}
}
