// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
)

type fakeLogoutNotifications struct {
	requests []*services.BackchannelLogoutRequest
	err      error
	calls    int
	received *contexts.LogoutNotificationContext
}

func (f *fakeLogoutNotifications) GetFrontChannelLogoutNotificationsUrls(ctx context.Context, notification *contexts.LogoutNotificationContext) ([]string, error) {
	return nil, nil
}

func (f *fakeLogoutNotifications) GetBackchannelLogoutNotifications(ctx context.Context, notification *contexts.LogoutNotificationContext) ([]*services.BackchannelLogoutRequest, error) {
	f.calls++
	f.received = notification
	return f.requests, f.err
}

// recordingLogoutPoster records every post; a URI can be made to fail, panic,
// or block until released.
type recordingLogoutPoster struct {
	mu      sync.Mutex
	posts   map[string]url.Values
	fail    map[string]error
	panics  map[string]bool
	blockOn map[string]chan struct{}
}

func newRecordingLogoutPoster() *recordingLogoutPoster {
	return &recordingLogoutPoster{
		posts:   map[string]url.Values{},
		fail:    map[string]error{},
		panics:  map[string]bool{},
		blockOn: map[string]chan struct{}{},
	}
}

func (p *recordingLogoutPoster) Post(target string, payload url.Values) error {
	p.mu.Lock()
	release := p.blockOn[target]
	shouldPanic := p.panics[target]
	err := p.fail[target]
	p.mu.Unlock()
	if release != nil {
		<-release
	}
	if shouldPanic {
		panic("relying party transport exploded")
	}
	p.mu.Lock()
	p.posts[target] = payload
	p.mu.Unlock()
	return err
}

func (p *recordingLogoutPoster) received() map[string]url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]url.Values, len(p.posts))
	for k, v := range p.posts {
		out[k] = v
	}
	return out
}

type mapClientStore map[string]*storage_models.Client

func (s mapClientStore) FindClientById(ctx context.Context, clientId string) (*storage_models.Client, error) {
	client, ok := s[clientId]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return client, nil
}

type staticIssuerName string

func (s staticIssuerName) GetCurrent() string { return string(s) }

func logoutClient(id string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	client.Enabled = true
	return client
}

type deliveryFixture struct {
	notifications *fakeLogoutNotifications
	poster        *recordingLogoutPoster
	clients       mapClientStore
	sessions      *sessionpkg.MemoryStore
	options       *config_options.WicketOptions
	logs          *bytes.Buffer
	service       *BackchannelLogoutService

	// record is the server-side session "session-1" seeded before sending;
	// by default it belongs to "bob" and lists every requested client.
	record *sessionpkg.Record
}

// deliveringOptions enables server-side sessions and the check-session
// endpoint, the assembly in which back-channel logout is delivered.
func deliveringOptions() *config_options.WicketOptions {
	options := config_options.NewWicketOptions()
	options.ServerSideSessions.Enabled = true
	options.Endpoints.EnableCheckSessionEndpoint = true
	return options
}

func newDeliveryFixture(requests ...*services.BackchannelLogoutRequest) *deliveryFixture {
	keys := NewKeyMaterialService(nil, nil, rs256Manager(), nil)
	creator := NewTokenCreationService(keys, test_common.NewStubClock(), config_options.NewWicketOptions(), nil)
	clients := mapClientStore{}
	for _, request := range requests {
		clients[request.ClientId] = logoutClient(request.ClientId)
	}
	clientIds := make([]string, 0, len(requests))
	for _, request := range requests {
		clientIds = append(clientIds, request.ClientId)
	}
	if len(clientIds) == 0 {
		clientIds = []string{"rp"}
	}
	clock := fixedClock{}
	logs := &bytes.Buffer{}
	f := &deliveryFixture{
		notifications: &fakeLogoutNotifications{requests: requests},
		poster:        newRecordingLogoutPoster(),
		clients:       clients,
		sessions:      sessionpkg.NewMemoryStore(clock),
		options:       deliveringOptions(),
		logs:          logs,
		record: &sessionpkg.Record{
			SessionID: "session-1",
			SubjectID: "bob",
			Created:   clock.Now(),
			Renewed:   clock.Now(),
			Expires:   clock.Now().Add(time.Hour),
			ClientIDs: clientIds,
		},
	}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.service = NewBackchannelLogoutService(f.notifications, f.poster, creator, clients,
		staticIssuerName("https://fallback.wicket.test"), f.sessions, clock, f.options, logger)
	return f
}

// send seeds the session record and delivers a logout context naming it and
// every client recorded for it, without naming a subject.
func (f *deliveryFixture) send(t *testing.T) {
	t.Helper()
	f.sendContext(t, &contexts.LogoutNotificationContext{
		SessionId: "session-1",
		ClientIds: append([]string(nil), f.record.ClientIDs...),
	})
}

func (f *deliveryFixture) sendContext(t *testing.T, notification *contexts.LogoutNotificationContext) {
	t.Helper()
	if f.record != nil {
		require.NoError(t, f.sessions.CreateSession(context.Background(), f.record))
	}
	require.NoError(t, f.service.SendLogoutNotificationsAsync(notification))
}

func decodeLogoutToken(t *testing.T, payload url.Values) (map[string]any, string) {
	t.Helper()
	raw := payload.Get("logout_token")
	require.NotEmpty(t, raw)
	msg, err := jws.Parse([]byte(raw))
	require.NoError(t, err)
	typ, _ := msg.Signatures()[0].ProtectedHeaders().Type()
	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(msg.Payload(), &claims))
	return claims, typ
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestBackchannelLogoutDeliversLogoutToken(t *testing.T) {
	f := newDeliveryFixture(&services.BackchannelLogoutRequest{
		ClientId:  "rp",
		LogoutUri: "https://rp.wicket.test/backchannel",
		SubjectId: "bob",
		SessionId: "session-1",
		Issuer:    "https://issuer.wicket.test",
	})

	f.send(t)

	posts := f.poster.received()
	require.Len(t, posts, 1)
	payload := posts["https://rp.wicket.test/backchannel"]
	require.Equal(t, []string{"logout_token"}, func() []string {
		names := make([]string, 0, len(payload))
		for name := range payload {
			names = append(names, name)
		}
		return names
	}())
	claims, typ := decodeLogoutToken(t, payload)

	require.Equal(t, "logout+jwt", typ)
	require.Equal(t, []string{"aud", "events", "exp", "iat", "iss", "jti", "nbf", "sid", "sub"}, keysOf(claims))
	require.Equal(t, "https://issuer.wicket.test", claims["iss"])
	// The JWT library serializes the single audience as a one-element array,
	// which RFC 7519 §4.1.3 treats the same as a string.
	require.Equal(t, []any{"rp"}, claims["aud"])
	require.Equal(t, "bob", claims["sub"])
	require.Equal(t, "session-1", claims["sid"])
	require.Equal(t, float64(LogoutTokenLifetimeSeconds), claims["exp"].(float64)-claims["iat"].(float64))
	require.Len(t, claims["jti"], 64)
	events, ok := claims["events"].(map[string]any)
	require.True(t, ok, "events must be a JSON object, got %T", claims["events"])
	event, ok := events[BackChannelLogoutEventType].(map[string]any)
	require.True(t, ok, "logout event must be a JSON object, got %T", events[BackChannelLogoutEventType])
	require.Empty(t, event)
	require.NotContains(t, claims, "nonce")

	require.NotContains(t, f.logs.String(), payload.Get("logout_token"))
}

func TestBackchannelLogoutJwtIdIsFreshPerToken(t *testing.T) {
	f := newDeliveryFixture(
		&services.BackchannelLogoutRequest{ClientId: "rp1", LogoutUri: "https://rp1.wicket.test/bc", SubjectId: "bob"},
		&services.BackchannelLogoutRequest{ClientId: "rp2", LogoutUri: "https://rp2.wicket.test/bc", SubjectId: "bob"},
	)

	f.send(t)

	posts := f.poster.received()
	require.Len(t, posts, 2)
	first, _ := decodeLogoutToken(t, posts["https://rp1.wicket.test/bc"])
	second, _ := decodeLogoutToken(t, posts["https://rp2.wicket.test/bc"])
	require.NotEqual(t, first["jti"], second["jti"])
	require.Equal(t, []any{"rp1"}, first["aud"])
	require.Equal(t, []any{"rp2"}, second["aud"])
}

func TestBackchannelLogoutSubjectAndSessionCombinations(t *testing.T) {
	for name, tc := range map[string]struct {
		sessionSubject, requestSessionId string
		required                         bool
		wantSent                         bool
		wantSub, wantSid                 bool
	}{
		"subject only":                   {sessionSubject: "bob", wantSent: true, wantSub: true},
		"session only":                   {requestSessionId: "session-1", wantSent: true, wantSid: true},
		"subject and session":            {sessionSubject: "bob", requestSessionId: "session-1", wantSent: true, wantSub: true, wantSid: true},
		"session required and present":   {sessionSubject: "bob", requestSessionId: "session-1", required: true, wantSent: true, wantSub: true, wantSid: true},
		"session required but missing":   {sessionSubject: "bob", required: true},
		"neither subject nor session id": {},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeliveryFixture(&services.BackchannelLogoutRequest{
				ClientId:          "rp",
				LogoutUri:         "https://rp.wicket.test/bc",
				SubjectId:         "ignored-request-subject",
				SessionId:         tc.requestSessionId,
				SessionIdRequired: tc.required,
			})
			f.record.SubjectID = tc.sessionSubject

			f.send(t)

			posts := f.poster.received()
			if !tc.wantSent {
				require.Empty(t, posts)
				return
			}
			claims, _ := decodeLogoutToken(t, posts["https://rp.wicket.test/bc"])
			_, hasSub := claims["sub"]
			_, hasSid := claims["sid"]
			require.Equal(t, tc.wantSub, hasSub)
			require.Equal(t, tc.wantSid, hasSid)
			if tc.wantSub {
				require.Equal(t, tc.sessionSubject, claims["sub"], "sub comes from the session record")
			}
		})
	}
}

func TestBackchannelLogoutSkipsUnusableLogoutUris(t *testing.T) {
	for name, uri := range map[string]string{
		"relative":    "/backchannel",
		"fragment":    "https://rp.wicket.test/bc#frag",
		"empty frag":  "https://rp.wicket.test/bc#",
		"non http":    "ftp://rp.wicket.test/bc",
		"no host":     "https:///bc",
		"port only":   "https://:443/bc",
		"unparseable": "https://rp.wicket.test/%zz",
		"scheme-less": "rp.wicket.test/bc",
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeliveryFixture(
				&services.BackchannelLogoutRequest{ClientId: "bad", LogoutUri: uri, SubjectId: "bob"},
				&services.BackchannelLogoutRequest{ClientId: "good", LogoutUri: "http://good.wicket.test/bc", SubjectId: "bob"},
			)

			f.send(t)

			posts := f.poster.received()
			require.Len(t, posts, 1)
			require.Contains(t, posts, "http://good.wicket.test/bc")
			require.Contains(t, f.logs.String(), `msg="back-channel logout: skipped, invalid logout uri" client_id=bad`)
		})
	}
}

func TestBackchannelLogoutSkipsDisabledOrUnknownClient(t *testing.T) {
	f := newDeliveryFixture(
		&services.BackchannelLogoutRequest{ClientId: "disabled", LogoutUri: "https://disabled.wicket.test/bc", SubjectId: "bob"},
		&services.BackchannelLogoutRequest{ClientId: "unknown", LogoutUri: "https://unknown.wicket.test/bc", SubjectId: "bob"},
		&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SubjectId: "bob"},
	)
	f.clients["disabled"].Enabled = false
	delete(f.clients, "unknown")

	f.send(t)

	posts := f.poster.received()
	require.Len(t, posts, 1)
	require.Contains(t, posts, "https://rp.wicket.test/bc")
}

func TestBackchannelLogoutFailingRelyingPartyDoesNotAffectOthers(t *testing.T) {
	f := newDeliveryFixture(
		&services.BackchannelLogoutRequest{ClientId: "failing", LogoutUri: "https://failing.wicket.test/bc", SubjectId: "bob"},
		&services.BackchannelLogoutRequest{ClientId: "panicking", LogoutUri: "https://panicking.wicket.test/bc", SubjectId: "bob"},
		&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SubjectId: "bob"},
	)
	f.poster.fail["https://failing.wicket.test/bc"] = errors.New("connection refused")
	f.poster.panics["https://panicking.wicket.test/bc"] = true

	f.send(t)

	posts := f.poster.received()
	require.Contains(t, posts, "https://rp.wicket.test/bc")
	require.Contains(t, f.logs.String(), `msg="back-channel logout: delivery failed" client_id=failing`)
	require.Contains(t, f.logs.String(), `msg="back-channel logout: delivery panicked" client_id=panicking`)
}

func TestBackchannelLogoutReturnsAtTheWaitBound(t *testing.T) {
	f := newDeliveryFixture(
		&services.BackchannelLogoutRequest{ClientId: "slow", LogoutUri: "https://slow.wicket.test/bc", SubjectId: "bob"},
		&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SubjectId: "bob"},
	)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.poster.blockOn["https://slow.wicket.test/bc"] = release
	f.service.timeout = 300 * time.Millisecond

	started := time.Now()
	f.send(t)
	elapsed := time.Since(started)

	require.Less(t, elapsed, 3*time.Second)
	require.Contains(t, f.poster.received(), "https://rp.wicket.test/bc")
	require.Contains(t, f.logs.String(), `msg="back-channel logout: delivery still running at the wait bound" client_ids=[slow]`)
}

func TestBackchannelLogoutFallsBackToTheCurrentIssuer(t *testing.T) {
	f := newDeliveryFixture(&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SubjectId: "bob"})

	f.send(t)

	claims, _ := decodeLogoutToken(t, f.poster.received()["https://rp.wicket.test/bc"])
	require.Equal(t, "https://fallback.wicket.test", claims["iss"])
}

func TestBackchannelLogoutSendsNothingWithoutParticipants(t *testing.T) {
	for name, notification := range map[string]*contexts.LogoutNotificationContext{
		"nil context":   nil,
		"no client ids": {SubjectId: "bob", SessionId: "session-1"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeliveryFixture(&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SubjectId: "bob"})

			require.NoError(t, f.service.SendLogoutNotificationsAsync(notification))

			require.Zero(t, f.notifications.calls)
			require.Empty(t, f.poster.received())
		})
	}
}

func TestBackchannelLogoutNotificationErrorIsNotReturned(t *testing.T) {
	f := newDeliveryFixture()
	f.notifications.err = errors.New("store unavailable")

	f.send(t)

	require.Empty(t, f.poster.received())
	require.Contains(t, f.logs.String(), "store unavailable")
}

func TestBackchannelLogoutWithoutCollaboratorsSendsNothing(t *testing.T) {
	service := NewBackchannelLogoutService(nil, nil, nil, nil, nil, nil, nil, deliveringOptions(), nil)
	require.NoError(t, service.SendLogoutNotificationsAsync(&contexts.LogoutNotificationContext{SubjectId: "bob", SessionId: "session-1", ClientIds: []string{"rp"}}))
}

func TestBackchannelLogoutDeclaresDeliveryOnlyWithSessionsAndCheckSession(t *testing.T) {
	for name, tc := range map[string]struct {
		sessions, checkSession bool
		want                   bool
	}{
		"sessions and check-session": {sessions: true, checkSession: true, want: true},
		"default assembly":           {sessions: false, checkSession: true},
		"check-session disabled":     {sessions: true, checkSession: false},
	} {
		t.Run(name, func(t *testing.T) {
			options := config_options.NewWicketOptions()
			options.ServerSideSessions.Enabled = tc.sessions
			options.Endpoints.EnableCheckSessionEndpoint = tc.checkSession
			service := NewBackchannelLogoutService(nil, nil, nil, nil, nil, nil, nil, options, nil)
			require.Equal(t, tc.want, service.DeliversBackChannelLogout())
		})
	}
	require.False(t, NewBackchannelLogoutService(nil, nil, nil, nil, nil, nil, nil, nil, nil).DeliversBackChannelLogout())
}

func TestBackchannelLogoutSendsNothingWhenNotDelivering(t *testing.T) {
	for name, configure := range map[string]func(*config_options.WicketOptions){
		"default assembly":       func(o *config_options.WicketOptions) { o.ServerSideSessions.Enabled = false },
		"check-session disabled": func(o *config_options.WicketOptions) { o.Endpoints.EnableCheckSessionEndpoint = false },
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeliveryFixture(&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SessionId: "session-1"})
			configure(f.options)

			f.send(t)

			require.Zero(t, f.notifications.calls)
			require.Empty(t, f.poster.received())
		})
	}
}

func TestBackchannelLogoutVerifiesTheContextAgainstTheSessionStore(t *testing.T) {
	request := func() *services.BackchannelLogoutRequest {
		return &services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SessionId: "session-1"}
	}
	for name, tc := range map[string]struct {
		prepare func(*deliveryFixture)
		context *contexts.LogoutNotificationContext
	}{
		"no session id": {
			context: &contexts.LogoutNotificationContext{ClientIds: []string{"rp"}},
		},
		"unknown session": {
			prepare: func(f *deliveryFixture) { f.record = nil },
			context: &contexts.LogoutNotificationContext{SessionId: "session-1", ClientIds: []string{"rp"}},
		},
		"expired session": {
			prepare: func(f *deliveryFixture) { f.record.Expires = fixedClock{}.Now().Add(-time.Second) },
			context: &contexts.LogoutNotificationContext{SessionId: "session-1", ClientIds: []string{"rp"}},
		},
		"subject differs from the session": {
			context: &contexts.LogoutNotificationContext{SubjectId: "mallory", SessionId: "session-1", ClientIds: []string{"rp"}},
		},
		"client not recorded for the session": {
			prepare: func(f *deliveryFixture) { f.record.ClientIDs = []string{"other"} },
			context: &contexts.LogoutNotificationContext{SessionId: "session-1", ClientIds: []string{"rp"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeliveryFixture(request())
			if tc.prepare != nil {
				tc.prepare(f)
			}

			f.sendContext(t, tc.context)

			require.Zero(t, f.notifications.calls)
			require.Empty(t, f.poster.received())
		})
	}
}

func TestBackchannelLogoutNarrowsClientsToTheSessionRecord(t *testing.T) {
	f := newDeliveryFixture(&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SessionId: "session-1"})
	notification := &contexts.LogoutNotificationContext{SubjectId: "bob", SessionId: "session-1", ClientIds: []string{"forged", "rp", "rp"}}

	f.sendContext(t, notification)

	require.NotNil(t, f.notifications.received)
	require.Equal(t, []string{"rp"}, f.notifications.received.ClientIds)
	require.Equal(t, "bob", f.notifications.received.SubjectId)
	require.Equal(t, []string{"forged", "rp", "rp"}, notification.ClientIds, "the caller's context is not modified")
}

func TestBackchannelLogoutDoesNotCarryAnIssuerNamedByTheLogoutContext(t *testing.T) {
	f := newDeliveryFixture(&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SessionId: "session-1"})
	notification := &contexts.LogoutNotificationContext{SessionId: "session-1", Issuer: "https://forged.wicket.test", ClientIds: []string{"rp"}}

	f.sendContext(t, notification)

	require.NotNil(t, f.notifications.received)
	require.Empty(t, f.notifications.received.Issuer)
	claims, _ := decodeLogoutToken(t, f.poster.received()["https://rp.wicket.test/bc"])
	require.Equal(t, "https://fallback.wicket.test", claims["iss"])
	require.Equal(t, "https://forged.wicket.test", notification.Issuer, "the caller's context is not modified")
}

func TestBackchannelLogoutSkipsAnExpiredSessionTheStoreStillReturns(t *testing.T) {
	f := newDeliveryFixture(&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SessionId: "session-1"})
	expired := *f.record
	expired.Expires = fixedClock{}.Now().Add(-time.Second)
	f.service.sessions = &unreapedSessionStore{Store: f.sessions, record: &expired}

	f.send(t)

	require.Zero(t, f.notifications.calls)
	require.Empty(t, f.poster.received())
	require.Contains(t, f.logs.String(), "level=WARN")
	require.Contains(t, f.logs.String(), "expired session")
}

func TestBackchannelLogoutReportsASessionStoreFailure(t *testing.T) {
	f := newDeliveryFixture(&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SessionId: "session-1"})
	f.service.sessions = &countingSessionStore{Store: f.sessions, err: errors.New("store unavailable")}

	f.send(t)

	require.Zero(t, f.notifications.calls)
	require.Empty(t, f.poster.received())
	require.Contains(t, f.logs.String(), "level=WARN")
	require.Contains(t, f.logs.String(), "cannot read the session")
	require.Contains(t, f.logs.String(), "store unavailable")
	require.NotContains(t, f.logs.String(), "unknown session")
}

func TestBackchannelLogoutReportsWhenNoClientIsRecordedForTheSession(t *testing.T) {
	f := newDeliveryFixture(&services.BackchannelLogoutRequest{ClientId: "rp", LogoutUri: "https://rp.wicket.test/bc", SessionId: "session-1"})
	f.record.ClientIDs = []string{"other"}

	f.sendContext(t, &contexts.LogoutNotificationContext{SessionId: "session-1", ClientIds: []string{"rp"}})

	require.Zero(t, f.notifications.calls)
	require.Empty(t, f.poster.received())
	require.Contains(t, f.logs.String(), "level=WARN")
	require.Contains(t, f.logs.String(), "no client of the logout context is recorded for the session")
}

// recordingTokenCreation records the tokens it is asked to sign.
type recordingTokenCreation struct {
	tokens []*storage_models.Token
}

func (r *recordingTokenCreation) CreateToken(ctx context.Context, token *storage_models.Token) (string, error) {
	r.tokens = append(r.tokens, token)
	return "signed", nil
}

func TestBackchannelLogoutSignsWithTheClientsIdentityTokenAlgorithms(t *testing.T) {
	f := newDeliveryFixture(
		&services.BackchannelLogoutRequest{ClientId: "restricted", LogoutUri: "https://restricted.wicket.test/bc", SessionId: "session-1"},
		&services.BackchannelLogoutRequest{ClientId: "open", LogoutUri: "https://open.wicket.test/bc", SessionId: "session-1"},
	)
	f.clients["restricted"].AllowedIdentityTokenSigningAlgorithms = []string{"ES256"}
	creator := &recordingTokenCreation{}
	f.service.tokens = creator

	f.send(t)

	require.Len(t, creator.tokens, 2)
	allowed := map[string][]string{}
	for _, token := range creator.tokens {
		require.Equal(t, TokenTypesLogoutToken, token.Type)
		require.Len(t, token.Audiences, 1)
		allowed[token.Audiences[0]] = token.AllowedSigningAlgorithms
	}
	require.Equal(t, []string{"ES256"}, allowed["restricted"])
	require.Empty(t, allowed["open"])
}
