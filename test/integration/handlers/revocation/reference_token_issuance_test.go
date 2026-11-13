// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package revocation

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	issuanceReferenceA        = "issuance.reference.a"
	issuanceReferenceB        = "issuance.reference.b"
	issuanceJwt               = "issuance.jwt"
	issuanceShortLived        = "issuance.reference.short"
	issuanceCodeReference     = "issuance.code.reference"
	issuanceCodeJwt           = "issuance.code.jwt"
	issuanceImplicitReference = "issuance.implicit.reference"
	issuanceImplicitJwt       = "issuance.implicit.jwt"
	issuanceHybridReference   = "issuance.hybrid.reference"
	issuanceHybridJwt         = "issuance.hybrid.jwt"

	issuanceRedirectUri = "https://client.example/callback"

	// issuanceShortLifetime is the access token lifetime, in seconds, of the
	// client used to observe expiry.
	issuanceShortLifetime = 3
)

var issuedHandlePattern = regexp.MustCompile(`^[0-9A-F]{64}$`)

// observedReferenceStore wraps the real in-memory store. It records the handle
// of every write it is asked for and can be switched to refuse writes, so a
// test can watch what the token endpoint stores without placing anything in
// the store itself.
type observedReferenceStore struct {
	*storage_impl.ReferenceTokenStore

	mu     sync.Mutex
	writes []string
	refuse func(handle string) error
}

func (s *observedReferenceStore) StoreReferenceToken(ctx context.Context, handle string, token *storage_models.Token) error {
	s.mu.Lock()
	s.writes = append(s.writes, handle)
	refuse := s.refuse
	s.mu.Unlock()
	if refuse != nil {
		return refuse(handle)
	}
	return s.ReferenceTokenStore.StoreReferenceToken(ctx, handle, token)
}

func (s *observedReferenceStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

// writesSince returns the handles written after the first n writes.
func (s *observedReferenceStore) writesSince(n int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.writes[n:]...)
}

func (s *observedReferenceStore) setRefuse(refuse func(handle string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse = refuse
}

type issuanceFixture struct {
	*revocationFixture
	store *observedReferenceStore
}

func issuanceClient(id string, tokenType wicket.AccessTokenType, grantTypes []string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	client.AccessTokenType = tokenType

	clientSecret := storage_models.NewSecret()
	clientSecret.Value = utils.Sha256(secret)
	client.ClientSecrets = []*storage_models.Secret{clientSecret}

	if err := client.SetAllowedGrantTypes(grantTypes); err != nil {
		panic(err)
	}
	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{wicket.StandardScopesOpenId, "api1"}
	client.RequirePkce = false
	client.RequireConsent = false
	client.RedirectUris = []string{issuanceRedirectUri}
	return client
}

func issuanceBrowserClient(id string, tokenType wicket.AccessTokenType, grantTypes []string) *storage_models.Client {
	client := issuanceClient(id, tokenType, grantTypes)
	client.RequireClientSecret = false
	client.AllowAccessTokensViaBrowser = true
	return client
}

// newIssuanceFixture assembles the real composition root with clients that
// differ only in their access token type. Nothing is placed in the reference
// token store: every reference token in these tests comes from the token or
// authorize endpoint.
func newIssuanceFixture(t *testing.T) *issuanceFixture {
	t.Helper()
	pipeline := integration_common.NewWicketPipeline()
	inner := storage_impl.NewReferenceTokenStore()
	observed := &observedReferenceStore{ReferenceTokenStore: inner}
	pipeline.Root.ServerConfig().SetReferenceTokenStore(observed)

	passwordAndClientCredentials := wicket.GrantTypesResourceOwnerPasswordAndClientCredentials
	shortLived := issuanceClient(issuanceShortLived, wicket.AccessTokenTypeReference, passwordAndClientCredentials)
	shortLived.AccessTokenLifetime = issuanceShortLifetime
	pipeline.Clients = append(pipeline.Clients,
		issuanceClient(issuanceReferenceA, wicket.AccessTokenTypeReference, passwordAndClientCredentials),
		issuanceClient(issuanceReferenceB, wicket.AccessTokenTypeReference, passwordAndClientCredentials),
		issuanceClient(issuanceJwt, wicket.AccessTokenTypeJwt, passwordAndClientCredentials),
		shortLived,
		issuanceClient(issuanceCodeReference, wicket.AccessTokenTypeReference, wicket.GrantTypesCode),
		issuanceClient(issuanceCodeJwt, wicket.AccessTokenTypeJwt, wicket.GrantTypesCode),
		issuanceBrowserClient(issuanceImplicitReference, wicket.AccessTokenTypeReference, wicket.GrantTypesImplicit),
		issuanceBrowserClient(issuanceImplicitJwt, wicket.AccessTokenTypeJwt, wicket.GrantTypesImplicit),
		issuanceBrowserClient(issuanceHybridReference, wicket.AccessTokenTypeReference, wicket.GrantTypesHybrid),
		issuanceBrowserClient(issuanceHybridJwt, wicket.AccessTokenTypeJwt, wicket.GrantTypesHybrid),
	)

	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	resource := storage_models.NewApiResource()
	resource.Name = "api1"
	apiSecret := storage_models.NewSecret()
	apiSecret.Value = utils.Sha256(secret)
	resource.ApiSecrets = []*storage_models.Secret{apiSecret}
	resource.Scopes = []string{"api1"}
	pipeline.ApiResources = append(pipeline.ApiResources, resource)

	scope := storage_models.NewApiScope()
	scope.Name = "api1"
	pipeline.ApiScopes = append(pipeline.ApiScopes, scope)

	bob := test.NewTestUser()
	bob.SubjectId = "1"
	bob.Username = "bob"
	bob.Password = "bob"
	alice := test.NewTestUser()
	alice.SubjectId = "2"
	alice.Username = "alice"
	alice.Password = "alice"
	pipeline.Users = append(pipeline.Users, bob, alice)

	pipeline.Initialize()
	return &issuanceFixture{
		revocationFixture: &revocationFixture{WicketPipeline: pipeline, referenceTokens: inner},
		store:             observed,
	}
}

type issuedTokens struct {
	body     string
	access   string
	refresh  string
	identity string
}

func parseIssuedTokens(body string) issuedTokens {
	return issuedTokens{
		body:     body,
		access:   gjson.Get(body, "access_token").String(),
		refresh:  gjson.Get(body, "refresh_token").String(),
		identity: gjson.Get(body, "id_token").String(),
	}
}

func (f *issuanceFixture) requestTokens(t *testing.T, form url.Values) issuedTokens {
	t.Helper()
	status, body := postToken(t, f.revocationFixture, form)
	require.Equal(t, http.StatusOK, status, "token endpoint: %s", body)
	tokens := parseIssuedTokens(body)
	require.NotEmpty(t, tokens.access)
	return tokens
}

func passwordForm(clientId string, username string, scope string) url.Values {
	return url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientId},
		"client_secret": {secret},
		"scope":         {scope},
		"username":      {username},
		"password":      {username},
	}
}

func (f *issuanceFixture) passwordGrant(t *testing.T, clientId string, username string, scope string) issuedTokens {
	t.Helper()
	return f.requestTokens(t, passwordForm(clientId, username, scope))
}

func (f *issuanceFixture) clientCredentialsGrant(t *testing.T, clientId string) issuedTokens {
	t.Helper()
	return f.requestTokens(t, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientId},
		"client_secret": {secret},
		"scope":         {"api1"},
	})
}

func (f *issuanceFixture) introspect(t *testing.T, token string) gjson.Result {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, f.TestServer.URL+integration_common.IntrospectionEndpoint, strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(t, err)
	request.SetBasicAuth("api1", secret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := f.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode, "introspection: %s", body)
	return gjson.ParseBytes(body)
}

func (f *issuanceFixture) active(t *testing.T, token string) bool {
	t.Helper()
	return introspectActive(t, f.revocationFixture, token)
}

func (f *issuanceFixture) userInfo(t *testing.T, token string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.TestServer.URL+integration_common.UserInfoEndpoint, nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := f.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response.StatusCode, string(body)
}

// storedRecord reads back the record the token endpoint stored under handle.
func (f *issuanceFixture) storedRecord(t *testing.T, handle string) *storage_models.Token {
	t.Helper()
	record, err := f.referenceTokens.GetReferenceToken(context.Background(), handle)
	require.NoError(t, err)
	require.NotNil(t, record)
	return record
}

func requireIssuedHandle(t *testing.T, token string) {
	t.Helper()
	require.Regexp(t, issuedHandlePattern, token)
	require.NotContains(t, token, ".")
	require.Len(t, token, 64)
}

func requireIssuedJwt(t *testing.T, token string) {
	t.Helper()
	require.Equal(t, 2, strings.Count(token, "."), "expected a three part JWT, got %q", token)
	require.NotRegexp(t, issuedHandlePattern, token)
}

func responseKeys(body string) []string {
	keys := make([]string, 0)
	gjson.Parse(body).ForEach(func(key, _ gjson.Result) bool {
		keys = append(keys, key.String())
		return true
	})
	sort.Strings(keys)
	return keys
}

// requireNoHandleTrace fails when text holds the handle or any eight character
// run of it.
func requireNoHandleTrace(t *testing.T, text string, handle string) {
	t.Helper()
	require.NotEmpty(t, handle)
	for start := 0; start+8 <= len(handle); start++ {
		require.NotContains(t, text, handle[start:start+8])
	}
}

// TestReferenceClientReceivesStoredHandle: a client configured for reference
// access tokens receives an opaque handle from the token endpoint and the
// token is kept in the reference token store; a client left on the default
// form receives a JWT from the same request and nothing is stored.
func TestReferenceClientReceivesStoredHandle(t *testing.T) {
	f := newIssuanceFixture(t)
	const scope = "openid api1 offline_access"

	// Control: the JWT client.
	before := f.store.writeCount()
	jwtTokens := f.passwordGrant(t, issuanceJwt, "bob", scope)
	requireIssuedJwt(t, jwtTokens.access)
	require.Empty(t, f.store.writesSince(before), "a JWT access token must not reach the reference token store")

	before = f.store.writeCount()
	referenceTokens := f.passwordGrant(t, issuanceReferenceA, "bob", scope)
	requireIssuedHandle(t, referenceTokens.access)
	require.Equal(t, []string{referenceTokens.access}, f.store.writesSince(before))

	t.Run("stored record", func(t *testing.T) {
		record := f.storedRecord(t, referenceTokens.access)
		require.Equal(t, issuanceReferenceA, record.ClientId)
		require.Equal(t, wicket.AccessTokenTypeReference, record.AccessTokenType)
		require.Equal(t, wicket.TokenTypesAccessToken, record.Type)
		require.Equal(t, 3600, record.Lifetime)
		require.False(t, record.CreationTime.IsZero())
		require.WithinDuration(t, time.Now(), record.CreationTime, time.Minute)
		require.NotEmpty(t, record.Issuer)
		require.Equal(t, []string{"api1"}, record.Audiences)
		require.Equal(t, "1", record.SubjectId())
		require.ElementsMatch(t, []string{"openid", "api1", "offline_access"}, record.Scopes())
		clientIdClaims := 0
		for _, claim := range record.Claims {
			if claim.Type == wicket.JwtClaimTypesClientId {
				clientIdClaims++
				require.Equal(t, issuanceReferenceA, claim.Value)
			}
		}
		require.Equal(t, 1, clientIdClaims)
	})

	t.Run("response differs only in the access token value", func(t *testing.T) {
		require.Equal(t, responseKeys(jwtTokens.body), responseKeys(referenceTokens.body))
		for _, key := range []string{"token_type", "expires_in", "scope"} {
			require.True(t, gjson.Get(referenceTokens.body, key).Exists(), "missing %s", key)
			require.Equal(t, gjson.Get(jwtTokens.body, key).String(), gjson.Get(referenceTokens.body, key).String(), key)
		}
		require.Equal(t, "Bearer", gjson.Get(referenceTokens.body, "token_type").String())
		require.Equal(t, int64(3600), gjson.Get(referenceTokens.body, "expires_in").Int())
		require.NotEmpty(t, referenceTokens.refresh)
	})

	t.Run("introspection", func(t *testing.T) {
		answer := f.introspect(t, referenceTokens.access)
		require.True(t, answer.Get("active").Bool(), "introspection: %s", answer.Raw)
		require.Equal(t, issuanceReferenceA, answer.Get("client_id").String())
		require.Equal(t, "1", answer.Get("sub").String())
		require.Contains(t, answer.Get("scope").String(), "api1")

		// Control: a string of the same shape that was never issued.
		neverIssued := strings.Repeat("0123456789ABCDEF", 4)
		requireIssuedHandle(t, neverIssued)
		require.False(t, f.introspect(t, neverIssued).Get("active").Bool())
	})
}

// TestIssuedReferenceTokenRevocation: the owning client revokes an issued
// handle at once; another client submitting it changes nothing.
func TestIssuedReferenceTokenRevocation(t *testing.T) {
	f := newIssuanceFixture(t)
	first := f.passwordGrant(t, issuanceReferenceA, "bob", "api1")
	second := f.passwordGrant(t, issuanceReferenceA, "bob", "api1")
	requireIssuedHandle(t, first.access)
	requireIssuedHandle(t, second.access)
	require.NotEqual(t, first.access, second.access)
	require.True(t, f.active(t, first.access))
	require.True(t, f.active(t, second.access))

	// Another client's submission answers 200 and revokes nothing.
	requireRevocationOk(t, revokeAs(t, f.revocationFixture, issuanceReferenceB, first.access, "access_token"))
	require.True(t, f.active(t, first.access))

	requireRevocationOk(t, revokeAs(t, f.revocationFixture, issuanceReferenceA, first.access, "access_token"))
	require.False(t, f.active(t, first.access))
	// Control: the client's other handle is untouched.
	require.True(t, f.active(t, second.access))
}

// TestIssuedReferenceTokensFollowRefreshTokenRevocation: redeeming a refresh
// token yields a new handle and keeps the earlier one; revoking the refresh
// token ends every handle of that subject and client and nothing else.
func TestIssuedReferenceTokensFollowRefreshTokenRevocation(t *testing.T) {
	f := newIssuanceFixture(t)
	const scope = "openid api1 offline_access"

	initial := f.passwordGrant(t, issuanceReferenceA, "bob", scope)
	requireIssuedHandle(t, initial.access)
	require.NotEmpty(t, initial.refresh)

	before := f.store.writeCount()
	renewed := f.requestTokens(t, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {issuanceReferenceA},
		"client_secret": {secret},
		"refresh_token": {initial.refresh},
	})
	requireIssuedHandle(t, renewed.access)
	require.NotEqual(t, initial.access, renewed.access)
	require.Equal(t, []string{renewed.access}, f.store.writesSince(before))
	refresh := renewed.refresh
	if refresh == "" {
		refresh = initial.refresh
	}

	otherClient := f.passwordGrant(t, issuanceReferenceB, "bob", scope)
	otherSubject := f.passwordGrant(t, issuanceReferenceA, "alice", scope)
	jwtTokens := f.passwordGrant(t, issuanceJwt, "bob", scope)
	requireIssuedHandle(t, otherClient.access)
	requireIssuedHandle(t, otherSubject.access)
	requireIssuedJwt(t, jwtTokens.access)

	// Before the revocation every token is active, the earlier handle included.
	for name, token := range map[string]string{
		"initial": initial.access, "renewed": renewed.access,
		"other client": otherClient.access, "other subject": otherSubject.access, "jwt": jwtTokens.access,
	} {
		require.True(t, f.active(t, token), "%s must start active", name)
	}

	requireRevocationOk(t, revokeAs(t, f.revocationFixture, issuanceReferenceA, refresh, "refresh_token"))

	require.False(t, f.active(t, initial.access))
	require.False(t, f.active(t, renewed.access))
	// Controls: same subject under another client, another subject under the
	// same client, and a JWT are all left alone.
	require.True(t, f.active(t, otherClient.access))
	require.True(t, f.active(t, otherSubject.access))
	require.True(t, f.active(t, jwtTokens.access))
}

// TestIssuedReferenceTokenAtUserInfo: an issued handle carrying the openid
// scope is accepted by userinfo until it is revoked.
func TestIssuedReferenceTokenAtUserInfo(t *testing.T) {
	f := newIssuanceFixture(t)
	referenceTokens := f.passwordGrant(t, issuanceReferenceA, "bob", "openid api1")
	jwtTokens := f.passwordGrant(t, issuanceJwt, "bob", "openid api1")
	requireIssuedHandle(t, referenceTokens.access)
	requireIssuedJwt(t, jwtTokens.access)

	status, body := f.userInfo(t, referenceTokens.access)
	require.Equal(t, http.StatusOK, status, "userinfo: %s", body)
	require.Equal(t, "1", gjson.Get(body, "sub").String())

	// Control: the JWT client's token is accepted as before.
	status, body = f.userInfo(t, jwtTokens.access)
	require.Equal(t, http.StatusOK, status, "userinfo: %s", body)
	require.Equal(t, "1", gjson.Get(body, "sub").String())

	requireRevocationOk(t, revokeAs(t, f.revocationFixture, issuanceReferenceA, referenceTokens.access, "access_token"))

	status, _ = f.userInfo(t, referenceTokens.access)
	require.Equal(t, http.StatusUnauthorized, status)
	status, _ = f.userInfo(t, jwtTokens.access)
	require.Equal(t, http.StatusOK, status)
}

// TestReferenceClientCredentialsGrant: a reference client without a subject
// receives a handle as well, and its owner can revoke it.
func TestReferenceClientCredentialsGrant(t *testing.T) {
	f := newIssuanceFixture(t)

	// Control: the JWT client.
	before := f.store.writeCount()
	jwtTokens := f.clientCredentialsGrant(t, issuanceJwt)
	requireIssuedJwt(t, jwtTokens.access)
	require.Empty(t, f.store.writesSince(before))

	first := f.clientCredentialsGrant(t, issuanceReferenceA)
	second := f.clientCredentialsGrant(t, issuanceReferenceA)
	requireIssuedHandle(t, first.access)
	requireIssuedHandle(t, second.access)
	require.Equal(t, []string{first.access, second.access}, f.store.writesSince(before))

	record := f.storedRecord(t, first.access)
	require.Equal(t, issuanceReferenceA, record.ClientId)
	require.Empty(t, record.SubjectId())

	require.True(t, f.active(t, first.access))
	require.True(t, f.active(t, second.access))

	requireRevocationOk(t, revokeAs(t, f.revocationFixture, issuanceReferenceA, first.access, "access_token"))
	require.False(t, f.active(t, first.access))
	require.True(t, f.active(t, second.access))
}

// TestIssuedReferenceTokenExpires: a handle stops being active once its
// lifetime has passed. The pipeline offers no controllable clock, so the test
// issues a handle from a client with a lifetime of a few seconds through the
// real token endpoint and waits it out; a handle of a long lived client
// issued at that moment shows the inactive answer comes from expiry.
func TestIssuedReferenceTokenExpires(t *testing.T) {
	f := newIssuanceFixture(t)

	shortLived := f.passwordGrant(t, issuanceShortLived, "bob", "api1")
	requireIssuedHandle(t, shortLived.access)
	require.Equal(t, int64(issuanceShortLifetime), gjson.Get(shortLived.body, "expires_in").Int())
	require.True(t, f.active(t, shortLived.access), "the handle must be active before it expires")

	time.Sleep(issuanceShortLifetime*time.Second + 1500*time.Millisecond)

	longLived := f.passwordGrant(t, issuanceReferenceA, "bob", "api1")
	require.False(t, f.active(t, shortLived.access))
	require.True(t, f.active(t, longLived.access))
}

// TestReferenceTokenStoreFailureIssuesNothing: when the store refuses the
// write the token endpoint issues no token of either form, and neither the
// handle the store was given nor the store's own error text reaches the
// response.
func TestReferenceTokenStoreFailureIssuesNothing(t *testing.T) {
	const marker = "store-side-detail-7f3a"

	for name, refuse := range map[string]func(handle string) error{
		"plain error": func(handle string) error {
			return fmt.Errorf("%s: key %s rejected", marker, handle)
		},
		"duplicate handle": func(handle string) error {
			return fmt.Errorf("%s: key %s: %w", marker, handle, storage.ErrDuplicateHandle)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			form := passwordForm(issuanceReferenceA, "bob", "openid api1 offline_access")

			var storeError error
			f.store.setRefuse(func(handle string) error {
				storeError = refuse(handle)
				return storeError
			})
			before := f.store.writeCount()

			status, body := postToken(t, f.revocationFixture, form)

			require.NotEqual(t, http.StatusOK, status, "token endpoint: %s", body)
			require.NotContains(t, body, "access_token")
			require.NotContains(t, body, "id_token")
			require.NotContains(t, body, "eyJ", "the response must not carry a JWT")

			// Control: the store was asked to write a real handle and its own
			// error does hold that handle and the marker.
			attempted := f.store.writesSince(before)
			require.Len(t, attempted, 1)
			requireIssuedHandle(t, attempted[0])
			require.Contains(t, storeError.Error(), attempted[0])
			require.Contains(t, storeError.Error(), marker)

			requireNoHandleTrace(t, body, attempted[0])
			require.NotContains(t, body, marker)
			require.NotContains(t, body, storage.ErrDuplicateHandle.Error())
			require.False(t, f.active(t, attempted[0]), "a handle that was never stored must not be active")

			// Control: the same fixture issues again once the store accepts writes.
			f.store.setRefuse(nil)
			status, body = postToken(t, f.revocationFixture, form)
			require.Equal(t, http.StatusOK, status, "token endpoint: %s", body)
			issued := parseIssuedTokens(body)
			requireIssuedHandle(t, issued.access)
			require.True(t, f.active(t, issued.access))
		})
	}
}

// TestReferenceClientAuthorizationCodeFlow: the identity token of a reference
// client stays a JWT; only the access token becomes a handle and only it is
// stored.
func TestReferenceClientAuthorizationCodeFlow(t *testing.T) {
	redeem := func(t *testing.T, f *issuanceFixture, clientId string) issuedTokens {
		t.Helper()
		require.NoError(t, f.Login("1"))
		authorization := f.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
			ClientId:     clientId,
			ResponseType: "code",
			Scope:        "openid api1",
			RedirectUri:  issuanceRedirectUri,
			State:        "123_state",
			Nonce:        "123_nonce",
		})
		require.NotNil(t, authorization)
		require.NotEmpty(t, authorization.Code())
		return f.requestTokens(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authorization.Code()},
			"redirect_uri":  {issuanceRedirectUri},
			"client_id":     {clientId},
			"client_secret": {secret},
		})
	}

	t.Run("reference client", func(t *testing.T) {
		f := newIssuanceFixture(t)
		before := f.store.writeCount()

		tokens := redeem(t, f, issuanceCodeReference)

		requireIssuedHandle(t, tokens.access)
		requireIssuedJwt(t, tokens.identity)
		require.Equal(t, []string{tokens.access}, f.store.writesSince(before), "only the access token is stored")
		require.True(t, f.active(t, tokens.access))
	})

	t.Run("jwt client", func(t *testing.T) {
		f := newIssuanceFixture(t)
		before := f.store.writeCount()

		tokens := redeem(t, f, issuanceCodeJwt)

		requireIssuedJwt(t, tokens.access)
		requireIssuedJwt(t, tokens.identity)
		require.Empty(t, f.store.writesSince(before))
	})
}

// TestReferenceClientAtAuthorizeEndpoint: an access token handed out by the
// authorize endpoint follows the client's access token type too, while the
// identity token in the same response stays a JWT.
func TestReferenceClientAtAuthorizeEndpoint(t *testing.T) {
	for name, tc := range map[string]struct {
		responseType    string
		referenceClient string
		jwtClient       string
	}{
		"implicit": {responseType: "id_token token", referenceClient: issuanceImplicitReference, jwtClient: issuanceImplicitJwt},
		"hybrid":   {responseType: "code id_token token", referenceClient: issuanceHybridReference, jwtClient: issuanceHybridJwt},
	} {
		authorize := func(t *testing.T, f *issuanceFixture, clientId string) (string, string) {
			t.Helper()
			require.NoError(t, f.Login("1"))
			authorization := f.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
				ClientId:     clientId,
				ResponseType: tc.responseType,
				Scope:        "openid api1",
				RedirectUri:  issuanceRedirectUri,
				State:        "123_state",
				Nonce:        "123_nonce",
			})
			require.NotNil(t, authorization)
			require.False(t, authorization.IsError(), "authorize response: %s", authorization.Raw)
			return authorization.AccessToken(), authorization.IdentityToken()
		}

		t.Run(name+" reference client", func(t *testing.T) {
			f := newIssuanceFixture(t)
			before := f.store.writeCount()

			accessToken, identityToken := authorize(t, f, tc.referenceClient)

			requireIssuedHandle(t, accessToken)
			requireIssuedJwt(t, identityToken)
			require.Equal(t, []string{accessToken}, f.store.writesSince(before))
			require.True(t, f.active(t, accessToken))
		})

		t.Run(name+" jwt client", func(t *testing.T) {
			f := newIssuanceFixture(t)
			before := f.store.writeCount()

			accessToken, identityToken := authorize(t, f, tc.jwtClient)

			requireIssuedJwt(t, accessToken)
			requireIssuedJwt(t, identityToken)
			require.Empty(t, f.store.writesSince(before))
			require.True(t, f.active(t, accessToken))
		})
	}
}
