// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/dp"
	responses_models "github.com/gonewx/wicket/responses/models"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// formerSessionId is long enough that a logged prefix of it cannot be
// mistaken for the whole id.
const formerSessionId = "seed-session-0123456789abcdef"

// sessionGrantStores records every removal by session the revoker asks for
// and fails the ones the test names.
type sessionGrantStores struct {
	calls []string
	fail  map[string]error
	// onCall, when set, runs on every removal before it is recorded.
	onCall func()
}

func (s *sessionGrantStores) record(ctx context.Context, store, sessionId string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.onCall != nil {
		s.onCall()
	}
	s.calls = append(s.calls, store+":"+sessionId)
	return s.fail[store]
}

type recordingCodeStore struct {
	storage.AuthorizationCodeStore
	*sessionGrantStores
}

func (s recordingCodeStore) RemoveAuthorizationCodesBySession(ctx context.Context, sessionId string) (int, error) {
	return 1, s.record(ctx, "codes", sessionId)
}

type recordingRefreshStore struct {
	storage.RefreshTokenStore
	*sessionGrantStores
}

func (s recordingRefreshStore) RemoveRefreshTokensBySession(ctx context.Context, sessionId string) (int, error) {
	return 2, s.record(ctx, "refresh", sessionId)
}

type recordingReferenceStore struct {
	storage.ReferenceTokenStore
	*sessionGrantStores
}

func (s recordingReferenceStore) RemoveReferenceTokensBySession(ctx context.Context, sessionId string) (int, error) {
	return 3, s.record(ctx, "reference", sessionId)
}

type recordingPersistedStore struct {
	storage.PersistedGrantStore
	*sessionGrantStores
}

func (s recordingPersistedStore) RemoveAll(ctx context.Context, filter *storage.PersistedGrantFilter) error {
	if err := filter.Validate(); err != nil {
		return err
	}
	if filter.SubjectId != "" || filter.ClientId != "" || len(filter.ClientIds) > 0 || filter.Type != "" || len(filter.Types) > 0 {
		return errors.New("the filter names more than the session")
	}
	return s.record(ctx, "persisted", filter.SessionId)
}

func (s *sessionGrantStores) revoker(logs *bytes.Buffer) *SessionGrantRevoker {
	return NewSessionGrantRevoker(
		recordingCodeStore{sessionGrantStores: s},
		recordingRefreshStore{sessionGrantStores: s},
		recordingReferenceStore{sessionGrantStores: s},
		recordingPersistedStore{sessionGrantStores: s},
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	)
}

func allRemovals(sessionId string) []string {
	return []string{"codes:" + sessionId, "refresh:" + sessionId, "reference:" + sessionId, "persisted:" + sessionId}
}

func TestSessionGrantRevokerRemovesTheSessionFromEveryStore(t *testing.T) {
	t.Parallel()
	stores := &sessionGrantStores{}
	logs := &bytes.Buffer{}

	require.NoError(t, stores.revoker(logs).Revoke(context.Background(), formerSessionId, "alice"))

	require.Equal(t, allRemovals(formerSessionId), stores.calls)
	require.Contains(t, logs.String(), "level=INFO")
	require.Contains(t, logs.String(), "formerSubject=alice")
	require.Contains(t, logs.String(), "authorizationCodes=1")
	require.Contains(t, logs.String(), "refreshTokens=2")
	require.Contains(t, logs.String(), "referenceTokens=3")
	require.NotContains(t, logs.String(), formerSessionId)
}

func TestSessionGrantRevokerIsNotCancelledWithTheRequest(t *testing.T) {
	t.Parallel()
	stores := &sessionGrantStores{}
	logs := &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, stores.revoker(logs).Revoke(ctx, formerSessionId, "alice"))

	require.Equal(t, allRemovals(formerSessionId), stores.calls)
	require.NotContains(t, logs.String(), "level=WARN")
}

func TestSessionGrantRevokerNeverRemovesWithoutASession(t *testing.T) {
	t.Parallel()
	stores := &sessionGrantStores{}
	logs := &bytes.Buffer{}

	require.NoError(t, stores.revoker(logs).Revoke(context.Background(), "", "alice"))

	require.Empty(t, stores.calls)
	require.Empty(t, logs.String())
}

func TestSessionGrantRevokerAsksEveryStoreWhenSomeFail(t *testing.T) {
	t.Parallel()
	for name, failing := range map[string][]string{
		"authorization codes": {"codes"},
		"refresh tokens":      {"refresh"},
		"reference tokens":    {"reference"},
		"persisted grants":    {"persisted"},
		"all stores":          {"codes", "refresh", "reference", "persisted"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stores := &sessionGrantStores{fail: map[string]error{}}
			var injected []error
			for _, store := range failing {
				err := errors.New(store + " unavailable for " + formerSessionId)
				stores.fail[store] = err
				injected = append(injected, err)
			}
			logs := &bytes.Buffer{}

			err := stores.revoker(logs).Revoke(context.Background(), formerSessionId, "alice")

			require.Error(t, err)
			for _, cause := range injected {
				require.ErrorIs(t, err, cause)
			}
			require.Equal(t, allRemovals(formerSessionId), stores.calls)
			require.Equal(t, 1, strings.Count(logs.String(), "level=WARN"), logs.String())
			require.NotContains(t, logs.String(), "level=INFO")
			require.NotContains(t, logs.String(), formerSessionId)
		})
	}
}

func TestSessionGrantRevokerSkipsAStoreItWasNotGiven(t *testing.T) {
	t.Parallel()
	stores := &sessionGrantStores{}

	require.NoError(t, NewSessionGrantRevoker(nil, recordingRefreshStore{sessionGrantStores: stores}, nil, recordingPersistedStore{sessionGrantStores: stores}, nil).Revoke(context.Background(), formerSessionId, "alice"))

	require.Equal(t, []string{"refresh:" + formerSessionId, "persisted:" + formerSessionId}, stores.calls)
}

// taggingProtector is an authenticating test protector: the protected form
// is the payload followed by its HMAC, and a value whose tag does not match
// fails to unprotect.
type taggingProtector struct{ key []byte }

func newTaggingProtector() *taggingProtector {
	return &taggingProtector{key: []byte("wicket session cookie test key")}
}

func (p *taggingProtector) Create(purpose string) dp.DataProtector {
	return &taggingProtector{key: append(append([]byte(nil), p.key...), purpose...)}
}

func (p *taggingProtector) tag(data []byte) []byte {
	mac := hmac.New(sha256.New, p.key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (p *taggingProtector) Protect(data []byte) []byte {
	return append(append([]byte(nil), data...), p.tag(data)...)
}

func (p *taggingProtector) Unprotect(data []byte) ([]byte, error) {
	if len(data) < sha256.Size {
		return nil, errors.New("protected value too short")
	}
	payload, tag := data[:len(data)-sha256.Size], data[len(data)-sha256.Size:]
	if !hmac.Equal(tag, p.tag(payload)) {
		return nil, errors.New("protected value was changed")
	}
	return append([]byte(nil), payload...), nil
}

// protectedSessionCookie is the session cookie value of sessionId under
// protector.
func protectedSessionCookie(protector dp.DataProtector, sessionId string) string {
	return base64.RawURLEncoding.EncodeToString(protector.Protect([]byte(sessionId)))
}

// revocationFixture is a request-scoped user session whose request carries
// the session cookie of formerSessionId, recorded for subject alice. While
// the revocation is on, the cookie carries the protected session id.
type revocationFixture struct {
	stores    *sessionGrantStores
	sessions  *countingSessionStore
	memory    *sessionpkg.MemoryStore
	recorder  *httptest.ResponseRecorder
	logs      *bytes.Buffer
	session   *UserSession
	clock     *sessionStateClock
	protector *taggingProtector
}

type revocationSetup struct {
	// sessionsDisabled turns server-side sessions off.
	sessionsDisabled bool
	// noRevoker leaves the revocation off.
	noRevoker bool
	// noCookie sends no session cookie.
	noCookie bool
	// record replaces the seeded record; with noRecord, none is seeded.
	record   *sessionpkg.Record
	noRecord bool
	// readErr fails every session read.
	readErr error
	// cookie, when set, is sent as the session cookie value as is.
	cookie string
}

func newRevocationFixture(t *testing.T, setup revocationSetup) *revocationFixture {
	t.Helper()
	clock := newSessionStateClock()
	memory := sessionpkg.NewMemoryStore(clock)
	var base sessionpkg.Store = memory
	switch {
	case setup.noRecord:
	case setup.record != nil:
		base = &unreapedSessionStore{Store: memory, record: setup.record}
	default:
		require.NoError(t, memory.CreateSession(context.Background(), &sessionpkg.Record{
			SessionID: formerSessionId,
			SubjectID: "alice",
			Created:   clock.Now(),
			Renewed:   clock.Now(),
			Expires:   clock.Now().Add(time.Hour),
			ClientIDs: []string{"client-a"},
		}))
	}
	sessions := &countingSessionStore{Store: base, err: setup.readErr}

	protector := newTaggingProtector()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	switch {
	case setup.noCookie:
	case setup.cookie != "":
		request.AddCookie(&http.Cookie{Name: "wicket.session", Value: setup.cookie})
	case setup.noRevoker:
		request.AddCookie(&http.Cookie{Name: "wicket.session", Value: formerSessionId})
	default:
		request.AddCookie(&http.Cookie{Name: "wicket.session", Value: protectedSessionCookie(protector, formerSessionId)})
	}
	recorder := httptest.NewRecorder()
	us := newSessionUserSession(t, !setup.sessionsDisabled, sessions, &recordingAccessor{req: request, rw: recorder}, clock)
	logs := &bytes.Buffer{}
	us.logger = slog.New(slog.NewTextHandler(logs, nil))
	stores := &sessionGrantStores{fail: map[string]error{}}
	if !setup.noRevoker {
		us.SetSessionGrantRevoker(stores.revoker(logs), protector)
	}
	return &revocationFixture{stores: stores, sessions: sessions, memory: memory, recorder: recorder, logs: logs, session: us, clock: clock, protector: protector}
}

// cookieSessionId returns the session id cookie carries: the cookie value
// while the revocation is off, the unprotected value while it is on.
func (f *revocationFixture) cookieSessionId(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	if f.session.revoker == nil {
		return cookie.Value
	}
	protected, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	require.NoError(t, err, "the session cookie is base64url")
	sessionId, err := f.protector.Unprotect(protected)
	require.NoError(t, err, "the session cookie holds a protected session id")
	require.NotEqual(t, string(sessionId), cookie.Value, "the session cookie does not carry the session id itself")
	return string(sessionId)
}

func (f *revocationFixture) sessionCookieCleared() bool {
	// The header map is read directly: the recorder's Result snapshots the
	// headers on its first call.
	for _, c := range (&http.Response{Header: f.recorder.Header()}).Cookies() {
		if c.Name == "wicket.session" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// writtenSessionCookie returns the last session cookie the response sets.
func (f *revocationFixture) writtenSessionCookie() *http.Cookie {
	var written *http.Cookie
	for _, c := range (&http.Response{Header: f.recorder.Header()}).Cookies() {
		if c.Name == "wicket.session" {
			written = c
		}
	}
	return written
}

// signIn signs subject in on a new session.
func (f *revocationFixture) signIn(t *testing.T, subject string) {
	t.Helper()
	f.signInOn(t, subject, false)
}

// signInOn signs subject in and checks that the sign-in continues the former
// session when continued is set, and starts a new one otherwise.
func (f *revocationFixture) signInOn(t *testing.T, subject string, continued bool) {
	t.Helper()
	created, err := f.session.CreateSessionId(context.Background(), principalWithSubject(subject), nil)
	require.NoError(t, err)
	require.NotEmpty(t, created)
	if continued {
		require.Equal(t, formerSessionId, created, "the sign-in continues the former session")
	} else {
		require.NotEqual(t, formerSessionId, created, "the sign-in starts a new session")
	}
	record, err := f.memory.GetSession(context.Background(), created)
	require.NoError(t, err, "the session is recorded")
	require.Equal(t, subject, record.SubjectID)
	cookie := f.writtenSessionCookie()
	require.NotNil(t, cookie, "the session cookie is written")
	require.Equal(t, created, f.cookieSessionId(t, cookie))
}

func TestUserSessionSignInRevokesTheFormerSubjectsGrants(t *testing.T) {
	t.Parallel()
	clock := newSessionStateClock()
	cases := map[string]struct {
		setup     revocationSetup
		subject   string
		revoked   bool
		continued bool
	}{
		"another subject signs in":        {subject: "bob", revoked: true},
		"the same subject signs in again": {subject: "alice", continued: true},
		"no former session cookie":        {setup: revocationSetup{noCookie: true}, subject: "bob"},
		"the former session is unknown":   {setup: revocationSetup{noRecord: true}, subject: "bob"},
		"the former session has expired": {
			setup: revocationSetup{record: &sessionpkg.Record{
				SessionID: formerSessionId,
				SubjectID: "alice",
				Created:   clock.Now().Add(-2 * time.Hour),
				Renewed:   clock.Now().Add(-2 * time.Hour),
				Expires:   clock.Now().Add(-time.Second),
			}},
			subject: "bob",
			revoked: true,
		},
		"the same subject's former session has expired": {
			setup: revocationSetup{record: &sessionpkg.Record{
				SessionID: formerSessionId,
				SubjectID: "alice",
				Created:   clock.Now().Add(-2 * time.Hour),
				Renewed:   clock.Now().Add(-2 * time.Hour),
				Expires:   clock.Now().Add(-time.Second),
			}},
			subject: "alice",
		},
		"the former session names no subject": {
			setup:   revocationSetup{record: &sessionpkg.Record{SessionID: formerSessionId, Expires: clock.Now().Add(time.Hour)}},
			subject: "bob",
		},
		"the former session names no subject and alice signs in": {
			setup:   revocationSetup{record: &sessionpkg.Record{SessionID: formerSessionId, SubjectID: "", Expires: clock.Now().Add(time.Hour)}},
			subject: "alice",
		},
		"revocation is off": {setup: revocationSetup{noRevoker: true}, subject: "bob"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t, tc.setup)

			f.signInOn(t, tc.subject, tc.continued)

			if tc.revoked {
				require.Equal(t, allRemovals(formerSessionId), f.stores.calls)
			} else {
				require.Empty(t, f.stores.calls)
			}
			record, err := f.sessions.Store.GetSession(context.Background(), formerSessionId)
			if !tc.setup.noRecord {
				require.NoError(t, err, "the former session record is kept")
				require.Equal(t, formerSessionId, record.SessionID)
			}
		})
	}
}

func TestUserSessionSignInWithoutRevocationDoesNotReadTheFormerSession(t *testing.T) {
	t.Parallel()
	for name, setup := range map[string]revocationSetup{
		"revocation is off":            {noRevoker: true},
		"server-side sessions are off": {sessionsDisabled: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t, setup)

			created, err := f.session.CreateSessionId(context.Background(), principalWithSubject("bob"), nil)
			require.NoError(t, err)
			require.NotEmpty(t, created)

			require.Zero(t, f.sessions.reads)
			require.Empty(t, f.stores.calls)
		})
	}
}

func TestUserSessionSignInSurvivesASessionStoreFailure(t *testing.T) {
	t.Parallel()
	for _, subject := range []string{"bob", "alice"} {
		t.Run(subject, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t, revocationSetup{readErr: errors.New("session store unavailable for " + formerSessionId)})

			created, err := f.session.CreateSessionId(context.Background(), principalWithSubject(subject), nil)
			require.NoError(t, err)
			require.NotEmpty(t, created)
			require.NotEqual(t, formerSessionId, created)

			require.Empty(t, f.stores.calls)
			require.Contains(t, f.logs.String(), "level=WARN")
			require.Contains(t, f.logs.String(), "cannot load the former session")
			require.NotContains(t, f.logs.String(), formerSessionId)
			record, err := f.memory.GetSession(context.Background(), formerSessionId)
			require.NoError(t, err)
			require.Equal(t, f.clock.now.Add(time.Hour), record.Expires, "the former session is not renewed")
		})
	}
}

// failingCreateSessionStore fails to record new sessions.
type failingCreateSessionStore struct{ sessionpkg.Store }

func (failingCreateSessionStore) CreateSession(context.Context, *sessionpkg.Record) error {
	return errors.New("session store full")
}

func TestUserSessionRevokesEvenWhenTheNewSessionCannotBeCreated(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, revocationSetup{})
	f.sessions.Store = failingCreateSessionStore{Store: f.sessions.Store}

	_, err := f.session.CreateSessionId(context.Background(), principalWithSubject("bob"), nil)
	require.ErrorContains(t, err, "session store full")

	require.Equal(t, allRemovals(formerSessionId), f.stores.calls)
}

func TestUserSessionSignInSurvivesAFailingGrantStore(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, revocationSetup{})
	f.stores.fail["refresh"] = errors.New("refresh tokens unavailable")

	f.signIn(t, "bob")

	require.Equal(t, allRemovals(formerSessionId), f.stores.calls)
	require.Equal(t, 1, strings.Count(f.logs.String(), "level=WARN"), f.logs.String())
	require.NotContains(t, f.logs.String(), formerSessionId)
}

func TestUserSessionRestoreRevokesWhenTheSubjectDoesNotMatch(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, revocationSetup{})
	f.session.user = principalWithSubject("bob")
	f.stores.onCall = func() {
		require.False(t, f.sessionCookieCleared(), "grants are revoked before the session cookie is cleared")
	}

	require.Empty(t, f.session.GetSessionId())

	require.Equal(t, allRemovals(formerSessionId), f.stores.calls)
	require.True(t, f.sessionCookieCleared())
}

func TestUserSessionRestoreDoesNotRevoke(t *testing.T) {
	t.Parallel()
	clock := newSessionStateClock()
	cases := map[string]struct {
		setup   revocationSetup
		subject string
	}{
		"the session's own subject": {subject: "alice"},
		"an anonymous request":      {},
		"an expired session": {
			setup: revocationSetup{record: &sessionpkg.Record{
				SessionID: formerSessionId,
				SubjectID: "alice",
				Expires:   clock.Now().Add(-time.Second),
			}},
			subject: "bob",
		},
		"revocation is off": {setup: revocationSetup{noRevoker: true}, subject: "bob"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t, tc.setup)
			if tc.subject != "" {
				f.session.user = principalWithSubject(tc.subject)
			}

			_ = f.session.GetSessionId()

			require.Empty(t, f.stores.calls)
		})
	}
}

func TestUserSessionRevokesTheFormerSessionOncePerRequest(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, revocationSetup{})
	f.session.user = principalWithSubject("bob")
	require.Empty(t, f.session.GetSessionId())

	f.signIn(t, "bob")

	require.Equal(t, allRemovals(formerSessionId), f.stores.calls)
}

func TestRefreshTokenRecordsItsSessionOnlyWhenBound(t *testing.T) {
	t.Parallel()
	sessionAccessToken := &models.Token{Claims: []*claims.Claim{
		claims.NewClaim(claims.WithClaimType(wicket.JwtClaimTypesSessionId), claims.WithClaimValue("session-1")),
	}}
	cases := map[string]struct {
		bound       bool
		accessToken *models.Token
		want        string
	}{
		"unbound":                    {accessToken: sessionAccessToken},
		"bound":                      {bound: true, accessToken: sessionAccessToken, want: "session-1"},
		"bound without access token": {bound: true},
		"bound outside of a session": {bound: true, accessToken: &models.Token{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newRotationStore()
			service := NewRefreshTokenService(store, NewHandleGenerationService())
			service.SetSessionBinding(tc.bound)
			client := models.NewClient()
			client.ClientId = "client"

			handle, err := service.CreateRefreshToken(context.Background(), &responses_models.RefreshTokenCreationRequest{
				Client:      client,
				AccessToken: tc.accessToken,
			})
			require.NoError(t, err)

			require.Equal(t, tc.want, getRefreshToken(t, store, handle).SessionId)
		})
	}
}

func TestUserSessionSameSubjectSignInRenewsTheFormerSession(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, revocationSetup{})
	before, err := f.memory.GetSession(context.Background(), formerSessionId)
	require.NoError(t, err)
	f.clock.now = f.clock.now.Add(30 * time.Minute)

	f.signInOn(t, "alice", true)

	require.Empty(t, f.stores.calls, "signing the same subject in again revokes nothing")
	require.Equal(t, 1, f.sessions.reads, "the former session is read once")
	after, err := f.memory.GetSession(context.Background(), formerSessionId)
	require.NoError(t, err)
	require.Equal(t, f.clock.now, after.Renewed)
	require.Equal(t, f.clock.now.Add(24*time.Hour), after.Expires)
	require.Equal(t, before.Created, after.Created)
	require.Equal(t, before.SubjectID, after.SubjectID)
	require.Equal(t, before.ClientIDs, after.ClientIDs)
	cookie := f.writtenSessionCookie()
	require.Equal(t, int((24 * time.Hour).Seconds()), cookie.MaxAge, "the session cookie is renewed")
	require.Equal(t, formerSessionId, f.session.GetSessionId())
	clients, err := f.session.GetClientList()
	require.NoError(t, err)
	require.Equal(t, []string{"client-a"}, clients, "the clients of the session carry over")
}

func TestUserSessionSignInWithoutRevocationNeverContinuesTheSession(t *testing.T) {
	t.Parallel()
	for name, setup := range map[string]revocationSetup{
		"revocation is off":            {noRevoker: true},
		"server-side sessions are off": {sessionsDisabled: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t, setup)

			created, err := f.session.CreateSessionId(context.Background(), principalWithSubject("alice"), nil)
			require.NoError(t, err)
			require.NotEmpty(t, created)
			require.NotEqual(t, formerSessionId, created)

			require.Zero(t, f.sessions.reads)
			require.Empty(t, f.stores.calls)
			record, err := f.memory.GetSession(context.Background(), formerSessionId)
			require.NoError(t, err)
			require.Equal(t, f.clock.now.Add(time.Hour), record.Expires, "the former session is not renewed")
		})
	}
}

// failingUpdateSessionStore fails to update session records.
type failingUpdateSessionStore struct{ sessionpkg.Store }

func (failingUpdateSessionStore) UpdateSession(context.Context, *sessionpkg.Record) error {
	return errors.New("session store read-only")
}

func TestUserSessionSignInFailsWhenTheSessionCannotBeRenewed(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, revocationSetup{})
	f.session.user = principalWithSubject("alice")
	require.Equal(t, formerSessionId, f.session.GetSessionId(), "the session is restored first")
	f.session.user = nil
	f.sessions.Store = failingUpdateSessionStore{Store: f.sessions.Store}

	created, err := f.session.CreateSessionId(context.Background(), principalWithSubject("alice"), nil)
	require.ErrorContains(t, err, "session store read-only")
	require.Empty(t, created)

	require.Empty(t, f.session.GetSessionId())
	require.Nil(t, f.session.GetUser())
	clients, err := f.session.GetClientList()
	require.NoError(t, err)
	require.Empty(t, clients, "no clients are left without a session")
	require.Nil(t, f.writtenSessionCookie(), "no session cookie is written")
	require.Empty(t, f.stores.calls)
	sessions, err := f.memory.GetSessionsBySubjectID(context.Background(), "alice")
	require.NoError(t, err)
	require.Len(t, sessions, 1, "no new session is created")

	// A store handing out its own record keeps it unrenewed.
	shared := &sessionpkg.Record{
		SessionID: formerSessionId,
		SubjectID: "alice",
		Renewed:   f.clock.now,
		Expires:   f.clock.now.Add(time.Hour),
	}
	g := newRevocationFixture(t, revocationSetup{noRecord: true})
	g.sessions.Store = failingUpdateSessionStore{Store: sharingSessionStore{record: shared}}
	g.clock.now = g.clock.now.Add(30 * time.Minute)
	_, err = g.session.CreateSessionId(context.Background(), principalWithSubject("alice"), nil)
	require.ErrorContains(t, err, "session store read-only")
	require.Equal(t, f.clock.now, shared.Renewed, "the stored record is not renewed")
	require.Equal(t, f.clock.now.Add(time.Hour), shared.Expires, "the stored record is not renewed")
}

// sharingSessionStore hands out its own record instead of a copy.
type sharingSessionStore struct {
	sessionpkg.Store
	record *sessionpkg.Record
}

func (s sharingSessionStore) GetSession(_ context.Context, sessionID string) (*sessionpkg.Record, error) {
	if s.record.SessionID != sessionID {
		return nil, sessionpkg.ErrSessionNotFound
	}
	return s.record, nil
}

func TestSessionContinues(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	cases := map[string]struct {
		record  *sessionpkg.Record
		subject string
		want    bool
	}{
		"the same subject":                                     {record: &sessionpkg.Record{SubjectID: "alice", Expires: now.Add(time.Minute)}, subject: "alice", want: true},
		"a session without expiry":                             {record: &sessionpkg.Record{SubjectID: "alice"}, subject: "alice", want: true},
		"another subject":                                      {record: &sessionpkg.Record{SubjectID: "alice", Expires: now.Add(time.Minute)}, subject: "bob"},
		"an expired session":                                   {record: &sessionpkg.Record{SubjectID: "alice", Expires: now.Add(-time.Second)}, subject: "alice"},
		"a session without a subject":                          {record: &sessionpkg.Record{Expires: now.Add(time.Minute)}, subject: ""},
		"a session without a subject and a subject signing in": {record: &sessionpkg.Record{Expires: now.Add(time.Minute)}, subject: "alice"},
		"no record":                                            {subject: "alice"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, sessionContinues(tc.record, tc.subject, now))
		})
	}
}

func TestSetSessionGrantRevokerRequiresACookieProtector(t *testing.T) {
	t.Parallel()
	stores := &sessionGrantStores{}
	us := &UserSession{}

	require.PanicsWithValue(t, "SetSessionGrantRevoker requires a session cookie protector together with the revoker", func() {
		us.SetSessionGrantRevoker(stores.revoker(&bytes.Buffer{}), nil)
	})
	require.Nil(t, us.revoker, "a revoker without a protector is not installed")

	protector := newTaggingProtector()
	us.SetSessionGrantRevoker(stores.revoker(&bytes.Buffer{}), protector)
	require.NotNil(t, us.revoker)
	require.Same(t, protector, us.cookieProtector)

	us.SetSessionGrantRevoker(nil, protector)
	require.Nil(t, us.revoker, "nil turns the revocation off")
	require.Nil(t, us.cookieProtector, "the protector is dropped with the revocation")
}

// forgedSessionCookies are session cookie values that do not hold a session
// id protected for the fixture.
func forgedSessionCookies() map[string]string {
	return map[string]string{
		"the plain session id": formerSessionId,
		// It decodes, so only unprotecting it can refuse it, as for a
		// plain hex session id.
		"the encoded plain session id": base64.RawURLEncoding.EncodeToString([]byte(formerSessionId)),
		"not base64url":                "not*base64url",
		"protected with another key": protectedSessionCookie(
			&taggingProtector{key: []byte("another key")}, formerSessionId),
	}
}

func TestUserSessionSignInTreatsAForgedSessionCookieAsNone(t *testing.T) {
	t.Parallel()
	for name, cookie := range forgedSessionCookies() {
		for _, subject := range []string{"bob", "alice"} {
			t.Run(name+"/"+subject, func(t *testing.T) {
				t.Parallel()
				f := newRevocationFixture(t, revocationSetup{cookie: cookie})

				f.signInOn(t, subject, false)

				require.Empty(t, f.stores.calls, "a forged session cookie revokes nothing")
				require.Zero(t, f.sessions.reads, "a forged session cookie names no session")
				require.True(t, f.sessionCookieCleared(), "the forged session cookie is cleared")
				record, err := f.memory.GetSession(context.Background(), formerSessionId)
				require.NoError(t, err)
				require.Equal(t, f.clock.now.Add(time.Hour), record.Expires, "the named session is not renewed")
			})
		}
	}
}

func TestUserSessionRestoreTreatsAForgedSessionCookieAsNone(t *testing.T) {
	t.Parallel()
	for name, cookie := range forgedSessionCookies() {
		for _, subject := range []string{"bob", "alice"} {
			t.Run(name+"/"+subject, func(t *testing.T) {
				t.Parallel()
				f := newRevocationFixture(t, revocationSetup{cookie: cookie})
				f.session.user = principalWithSubject(subject)

				require.Empty(t, f.session.GetSessionId())

				require.Empty(t, f.stores.calls)
				require.Zero(t, f.sessions.reads)
				require.True(t, f.sessionCookieCleared())
			})
		}
	}
}

func TestUserSessionEnsureTreatsAForgedSessionCookieAsNone(t *testing.T) {
	t.Parallel()
	for name, cookie := range forgedSessionCookies() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t, revocationSetup{cookie: cookie})
			f.session.user = principalWithSubject("alice")

			require.NoError(t, f.session.EnsureSessionIdCookie(context.Background()))

			require.Empty(t, f.session.session)
			require.Empty(t, f.stores.calls)
			require.Zero(t, f.sessions.reads)
			require.True(t, f.sessionCookieCleared())
		})
	}
}

func TestUserSessionProtectedSessionCookieRoundTrips(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, revocationSetup{noCookie: true})
	created, err := f.session.CreateSessionId(context.Background(), principalWithSubject("alice"), nil)
	require.NoError(t, err)
	written := f.writtenSessionCookie()
	require.NotNil(t, written)
	require.NotEqual(t, created, written.Value, "the session cookie does not carry the session id")
	require.NotContains(t, written.Value, created)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "wicket.session", Value: written.Value})
	next := newSessionUserSession(t, true, f.sessions, &recordingAccessor{req: request, rw: httptest.NewRecorder()}, f.clock)
	next.SetSessionGrantRevoker(f.stores.revoker(f.logs), f.protector)
	next.user = principalWithSubject("alice")

	require.Equal(t, created, next.GetSessionId())
}

func TestUserSessionEnsureAdoptsOnlyAsRestoreDoes(t *testing.T) {
	t.Parallel()
	clock := newSessionStateClock()
	expired := func() *sessionpkg.Record {
		return &sessionpkg.Record{
			SessionID: formerSessionId,
			SubjectID: "alice",
			Expires:   clock.Now().Add(-time.Second),
			ClientIDs: []string{"client-a"},
		}
	}
	cases := map[string]struct {
		setup   revocationSetup
		subject string
		adopted bool
	}{
		"the session's own subject":          {subject: "alice", adopted: true},
		"another subject":                    {subject: "bob"},
		"no authenticated user":              {},
		"an expired session":                 {setup: revocationSetup{record: expired()}, subject: "alice"},
		"revocation off, the own subject":    {setup: revocationSetup{noRevoker: true}, subject: "alice", adopted: true},
		"revocation off, another subject":    {setup: revocationSetup{noRevoker: true}, subject: "bob", adopted: true},
		"revocation off, no user":            {setup: revocationSetup{noRevoker: true}, adopted: true},
		"revocation off, an expired session": {setup: revocationSetup{noRevoker: true, record: expired()}, subject: "alice", adopted: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t, tc.setup)
			if tc.subject != "" {
				f.session.user = principalWithSubject(tc.subject)
			}

			require.NoError(t, f.session.EnsureSessionIdCookie(context.Background()))

			require.Empty(t, f.stores.calls, "ensuring the session cookie revokes nothing")
			if tc.adopted {
				require.Equal(t, formerSessionId, f.session.session)
				require.Equal(t, []string{"client-a"}, f.session.clients)
				require.False(t, f.sessionCookieCleared())
			} else {
				require.Empty(t, f.session.session)
				require.Empty(t, f.session.clients)
				require.True(t, f.sessionCookieCleared(), "the session cookie is cleared")
			}
		})
	}
}
