// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sessionpkg "github.com/gonewx/wicket/session"
)

// countingSessionStore counts session reads and can fail them.
type countingSessionStore struct {
	sessionpkg.Store
	reads int
	err   error
}

func (s *countingSessionStore) GetSession(ctx context.Context, sessionID string) (*sessionpkg.Record, error) {
	s.reads++
	if s.err != nil {
		return nil, s.err
	}
	return s.Store.GetSession(ctx, sessionID)
}

// unreapedSessionStore returns its record as stored, even when it has expired:
// a session store is not required to drop expired records on read.
type unreapedSessionStore struct {
	sessionpkg.Store
	record *sessionpkg.Record
}

func (s *unreapedSessionStore) GetSession(ctx context.Context, sessionID string) (*sessionpkg.Record, error) {
	if s.record == nil || s.record.SessionID != sessionID {
		return nil, sessionpkg.ErrSessionNotFound
	}
	copied := *s.record
	return &copied, nil
}

type restoreFixture struct {
	store    *countingSessionStore
	recorder *httptest.ResponseRecorder
	logs     *bytes.Buffer
	session  *UserSession
}

// newRestoreFixture seeds a session of subject "alice" and builds a fresh
// request-scoped UserSession whose request carries that session's cookie.
func newRestoreFixture(t *testing.T, enabled bool) *restoreFixture {
	t.Helper()
	clock := newSessionStateClock()
	memory := sessionpkg.NewMemoryStore(clock)
	require.NoError(t, memory.CreateSession(context.Background(), &sessionpkg.Record{
		SessionID: "seed-session",
		SubjectID: "alice",
		Created:   clock.Now(),
		Renewed:   clock.Now(),
		Expires:   clock.Now().Add(time.Hour),
		ClientIDs: []string{"client-a"},
	}))
	store := &countingSessionStore{Store: memory}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "wicket.session", Value: "seed-session"})
	recorder := httptest.NewRecorder()
	us := newSessionUserSession(t, enabled, store, &recordingAccessor{req: request, rw: recorder}, clock)
	logs := &bytes.Buffer{}
	us.logger = slog.New(slog.NewTextHandler(logs, nil))
	return &restoreFixture{store: store, recorder: recorder, logs: logs, session: us}
}

func (f *restoreFixture) sessionCookieCleared() bool {
	for _, c := range f.recorder.Result().Cookies() {
		if c.Name == "wicket.session" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestUserSessionRestoresTheSessionOfTheSignedInSubject(t *testing.T) {
	f := newRestoreFixture(t, true)
	f.session.user = principalWithSubject("alice")

	require.Equal(t, "seed-session", f.session.GetSessionId())
	clients, err := f.session.GetClientList()
	require.NoError(t, err)
	require.Equal(t, []string{"client-a"}, clients)
	require.False(t, f.sessionCookieCleared())
}

func TestUserSessionRestoresAtMostOncePerInstance(t *testing.T) {
	f := newRestoreFixture(t, true)

	require.Empty(t, f.session.GetSessionId())
	_, _ = f.session.GetClientList()
	require.NoError(t, f.session.AddClientId(context.Background(), "client-b"))
	require.Empty(t, f.session.GetSessionId())

	require.Equal(t, 1, f.store.reads)
}

func TestUserSessionRestoresWhenAClientIsFirstRecorded(t *testing.T) {
	f := newRestoreFixture(t, true)
	f.session.user = principalWithSubject("alice")

	require.NoError(t, f.session.AddClientId(context.Background(), "client-b"))

	record, err := f.store.GetSession(context.Background(), "seed-session")
	require.NoError(t, err)
	require.Equal(t, []string{"client-a", "client-b"}, record.ClientIDs, "the client is recorded for the restored session")
	require.Equal(t, "seed-session", f.session.GetSessionId())
	clients, err := f.session.GetClientList()
	require.NoError(t, err)
	require.Equal(t, []string{"client-a", "client-b"}, clients)
	require.False(t, f.sessionCookieCleared())
}

func TestUserSessionDoesNotAdoptAnotherSubjectsSession(t *testing.T) {
	for name, subject := range map[string]string{
		"different subject":   "mallory",
		"anonymous requester": "",
	} {
		t.Run(name, func(t *testing.T) {
			f := newRestoreFixture(t, true)
			if subject != "" {
				f.session.user = principalWithSubject(subject)
			}

			require.Empty(t, f.session.GetSessionId())
			clients, err := f.session.GetClientList()
			require.NoError(t, err)
			require.Empty(t, clients)
			require.True(t, f.sessionCookieCleared())
		})
	}
}

func TestUserSessionDoesNotRestoreAfterCreateOrRemove(t *testing.T) {
	t.Run("after a session was created", func(t *testing.T) {
		f := newRestoreFixture(t, true)
		created, err := f.session.CreateSessionId(context.Background(), principalWithSubject("alice"), nil)
		require.NoError(t, err)

		require.Equal(t, created, f.session.GetSessionId())
		require.Zero(t, f.store.reads)
	})

	t.Run("after the session was removed", func(t *testing.T) {
		f := newRestoreFixture(t, true)
		f.session.user = principalWithSubject("alice")
		require.NoError(t, f.session.RemoveSessionIdCookie())

		require.Empty(t, f.session.GetSessionId())
		require.Zero(t, f.store.reads)
	})
}

func TestUserSessionDisabledDoesNotReadTheSessionCookie(t *testing.T) {
	f := newRestoreFixture(t, false)
	f.session.user = principalWithSubject("alice")

	require.Empty(t, f.session.GetSessionId())
	require.Zero(t, f.store.reads)
	require.False(t, f.sessionCookieCleared())
}

func TestUserSessionStoreFailureIsTreatedAsNoSession(t *testing.T) {
	f := newRestoreFixture(t, true)
	f.session.user = principalWithSubject("alice")
	f.store.err = errors.New("store unavailable")

	require.Empty(t, f.session.GetSessionId())
	require.Contains(t, f.logs.String(), "store unavailable")
	require.Contains(t, f.logs.String(), "level=WARN")
	require.False(t, f.sessionCookieCleared(), "a store failure leaves the session cookie for a later request")
}

func TestUserSessionDoesNotRestoreAnExpiredSession(t *testing.T) {
	f := newRestoreFixture(t, true)
	f.session.user = principalWithSubject("alice")
	clock := newSessionStateClock()
	f.session.store = &unreapedSessionStore{Store: f.store, record: &sessionpkg.Record{
		SessionID: "seed-session",
		SubjectID: "alice",
		Created:   clock.Now().Add(-2 * time.Hour),
		Renewed:   clock.Now().Add(-2 * time.Hour),
		Expires:   clock.Now().Add(-time.Second),
		ClientIDs: []string{"client-a"},
	}}

	require.Empty(t, f.session.GetSessionId())
	clients, err := f.session.GetClientList()
	require.NoError(t, err)
	require.Empty(t, clients)
	require.True(t, f.sessionCookieCleared())
}

func TestUserSessionClearsTheCookieOfAnUnknownSession(t *testing.T) {
	f := newRestoreFixture(t, true)
	f.session.user = principalWithSubject("alice")
	f.session.store = &unreapedSessionStore{Store: f.store}

	require.Empty(t, f.session.GetSessionId())
	require.True(t, f.sessionCookieCleared())
}
