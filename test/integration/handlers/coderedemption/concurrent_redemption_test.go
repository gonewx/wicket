// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package coderedemption

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	ownerClient   = "redemption.owner"
	foreignClient = "redemption.foreign"
	clientSecret  = "secret"
	redirectUri   = "https://client.example/callback"

	// concurrentRedemptions is how many token requests race for one code.
	concurrentRedemptions = 10
	// barrierTimeout bounds how long a read waits for its siblings, so a
	// redemption path that reads fewer times than expected still finishes.
	barrierTimeout = 5 * time.Second
)

// barrierCodeStore wraps the real in-memory authorization code store. Once
// armed, every read of a code performs the read and then blocks until the
// expected number of readers has arrived (or the timeout passes), so a
// redemption built as a read followed by a removal lets every racing request
// observe the code before any of them removes it. The atomic take is forwarded unchanged: a
// redemption that takes never passes through the barrier.
type barrierCodeStore struct {
	*storage_impl.AuthorizationCodeStore

	mu       sync.Mutex
	armed    bool
	expected int
	arrived  int
	release  chan struct{}
}

func (s *barrierCodeStore) arm(expected int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armed = true
	s.expected = expected
	s.arrived = 0
	s.release = make(chan struct{})
}

func (s *barrierCodeStore) GetAuthorizationCode(ctx context.Context, handle string) (*storage_models.AuthorizationCode, error) {
	// Read first, then wait: every racing reader holds its result before any
	// of them is released to remove the code.
	code, err := s.AuthorizationCodeStore.GetAuthorizationCode(ctx, handle)
	s.mu.Lock()
	release := s.release
	if s.armed {
		s.arrived++
		if s.arrived == s.expected {
			close(s.release)
		}
	}
	armed := s.armed
	s.mu.Unlock()
	if armed {
		select {
		case <-release:
		case <-time.After(barrierTimeout):
		case <-ctx.Done():
		}
	}
	return code, err
}

func (s *barrierCodeStore) TakeAuthorizationCode(ctx context.Context, handle string) (*storage_models.AuthorizationCode, error) {
	return s.AuthorizationCodeStore.TakeAuthorizationCode(ctx, handle)
}

func codeClient(id string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(clientSecret)
	client.ClientSecrets = []*storage_models.Secret{secret}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCode); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId, "api1"}
	client.RequirePkce = false
	client.RequireConsent = false
	client.RedirectUris = []string{redirectUri}
	return client
}

type redemptionFixture struct {
	*integration_common.WicketPipeline
}

// newRedemptionFixture assembles the real composition root with two clients
// allowed the authorization code grant. When codes is non-nil it is injected
// as the authorization code store.
func newRedemptionFixture(t *testing.T, codes *barrierCodeStore) *redemptionFixture {
	t.Helper()
	pipeline := integration_common.NewWicketPipeline()
	if codes != nil {
		pipeline.Root.ServerConfig().SetAuthorizationCodeStore(codes)
	}
	pipeline.Clients = append(pipeline.Clients, codeClient(ownerClient), codeClient(foreignClient))
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

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
	return &redemptionFixture{WicketPipeline: pipeline}
}

// issueCode logs bob in and runs the authorize endpoint for clientId,
// returning the authorization code.
func (f *redemptionFixture) issueCode(t *testing.T, clientId string) string {
	t.Helper()
	require.NoError(t, f.Login("1"))
	authorization := f.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "code",
		Scope:        "openid api1",
		RedirectUri:  redirectUri,
		State:        "state",
		Nonce:        "nonce",
	})
	require.NotNil(t, authorization)
	require.NotEmpty(t, authorization.Code())
	return authorization.Code()
}

type tokenOutcome struct {
	status int
	body   string
	err    error
}

// redeem posts an authorization code exchange. It does not assert, so it can
// run on a worker goroutine; the caller asserts on the returned outcome.
func (f *redemptionFixture) redeem(clientId string, code string) tokenOutcome {
	response, err := f.BackChannelClient.PostForm(f.TestServer.URL+integration_common.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectUri},
		"client_id":     {clientId},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return tokenOutcome{err: err}
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	return tokenOutcome{status: response.StatusCode, body: string(body), err: err}
}

func requireInvalidGrant(t *testing.T, outcome tokenOutcome) {
	t.Helper()
	require.NoError(t, outcome.err)
	require.Equal(t, http.StatusBadRequest, outcome.status, "token endpoint: %s", outcome.body)
	require.Equal(t, "invalid_grant", gjson.Get(outcome.body, "error").String(), "token endpoint: %s", outcome.body)
}

// TestConcurrentRedemptionSucceedsOnce: many simultaneous exchanges of one
// code yield exactly one token response; every other request is told the
// grant is invalid, and none fails with a server error.
func TestConcurrentRedemptionSucceedsOnce(t *testing.T) {
	codes := &barrierCodeStore{AuthorizationCodeStore: storage_impl.NewAuthorizationCodeStore()}
	f := newRedemptionFixture(t, codes)
	code := f.issueCode(t, ownerClient)

	codes.arm(concurrentRedemptions)
	start := make(chan struct{})
	outcomes := make([]tokenOutcome, concurrentRedemptions)
	var wg sync.WaitGroup
	for i := 0; i < concurrentRedemptions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			outcomes[i] = f.redeem(ownerClient, code)
		}(i)
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for _, outcome := range outcomes {
		require.NoError(t, outcome.err)
		require.Less(t, outcome.status, http.StatusInternalServerError, "token endpoint: %s", outcome.body)
		if outcome.status == http.StatusOK {
			require.NotEmpty(t, gjson.Get(outcome.body, "access_token").String(), "token endpoint: %s", outcome.body)
			succeeded++
			continue
		}
		requireInvalidGrant(t, outcome)
	}
	require.Equal(t, 1, succeeded, "successful exchanges of one code")
}

// TestForeignClientRedemptionBurnsCode: a client presenting another client's
// code is refused, and the code is gone afterwards, so the rightful client is
// refused as well.
func TestForeignClientRedemptionBurnsCode(t *testing.T) {
	f := newRedemptionFixture(t, nil)
	code := f.issueCode(t, ownerClient)

	requireInvalidGrant(t, f.redeem(foreignClient, code))
	requireInvalidGrant(t, f.redeem(ownerClient, code))
}
