// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/services"
)

type recordingAuthService struct {
	auth.Service
	signedOut []string
}

func (s *recordingAuthService) SignOut(_ *http.Request, _ http.ResponseWriter, scheme string, _ *auth.Properties) error {
	s.signedOut = append(s.signedOut, scheme)
	return nil
}

type defaultSignOutSchemes struct {
	auth.SchemeProvider
	name string
}

func (s defaultSignOutSchemes) GetDefaultSignOutScheme() *auth.Scheme {
	return auth.NewScheme(s.name, "handler")
}

type removalRecordingSession struct {
	services.UserSession
	removed int
	err     error
}

func (s *removalRecordingSession) RemoveSessionIdCookie() error {
	s.removed++
	return s.err
}

func TestSignOutEndsTheSessionCookieOnlyForTheDefaultScheme(t *testing.T) {
	for name, tc := range map[string]struct {
		scheme      string
		wantRemoved int
	}{
		"unnamed scheme":            {scheme: "", wantRemoved: 1},
		"default sign-out scheme":   {scheme: "cookies", wantRemoved: 1},
		"temporary external scheme": {scheme: "external", wantRemoved: 0},
	} {
		t.Run(name, func(t *testing.T) {
			inner := &recordingAuthService{}
			session := &removalRecordingSession{}
			service := NewWicketAuthenticationService(
				wicket.NewDecorator[auth.Service](inner),
				defaultSignOutSchemes{name: "cookies"},
				nil, session, discardLogger(), nil,
			)

			err := service.SignOut(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder(), tc.scheme, nil)

			require.NoError(t, err)
			require.Equal(t, tc.wantRemoved, session.removed)
			require.Equal(t, []string{tc.scheme}, inner.signedOut)
		})
	}
}

func TestSignOutStillDelegatesWhenTheSessionCookieCannotBeRemoved(t *testing.T) {
	inner := &recordingAuthService{}
	session := &removalRecordingSession{err: errors.New("cookie failure")}
	service := NewWicketAuthenticationService(
		wicket.NewDecorator[auth.Service](inner),
		defaultSignOutSchemes{name: "cookies"},
		nil, session, discardLogger(), nil,
	)

	require.NoError(t, service.SignOut(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder(), "", nil))
	require.Equal(t, 1, session.removed)
	require.Equal(t, []string{""}, inner.signedOut)
}
