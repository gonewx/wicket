// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/hosting"
	"github.com/stretchr/testify/require"
)

// requestHandlerSpy is an auth.RequestHandler test double. It reports ownership
// of the request through should, records HandleRequest invocations, and — when
// it handles — writes a status through the response captured at Initialize, so a
// test can assert both the short-circuit and that the response came from the
// handler rather than downstream.
type requestHandlerSpy struct {
	should      bool
	handled     bool
	handleErr   error
	handleCalls int
	response    http.ResponseWriter
}

func (h *requestHandlerSpy) Initialize(_ *http.Request, w http.ResponseWriter, _ *auth.Scheme) error {
	h.response = w
	return nil
}
func (h *requestHandlerSpy) Authenticate() (*auth.Result, error) { return auth.NoResult(), nil }
func (h *requestHandlerSpy) Challenge(*auth.Properties) error    { return nil }
func (h *requestHandlerSpy) Forbid(*auth.Properties) error       { return nil }
func (h *requestHandlerSpy) ShouldHandleRequest() bool           { return h.should }
func (h *requestHandlerSpy) HandleRequest() (bool, error) {
	h.handleCalls++
	if h.handled && h.response != nil {
		h.response.WriteHeader(http.StatusFound)
	}
	return h.handled, h.handleErr
}

var _ auth.RequestHandler = (*requestHandlerSpy)(nil)

// plainHandler is an auth.Handler double that deliberately does not implement
// auth.RequestHandler, standing in for a scheme registered as a request
// handler whose resolved handler misses the contract.
type plainHandler struct{}

func (plainHandler) Initialize(*http.Request, http.ResponseWriter, *auth.Scheme) error { return nil }
func (plainHandler) Authenticate() (*auth.Result, error)                               { return auth.NoResult(), nil }
func (plainHandler) Challenge(*auth.Properties) error                                  { return nil }
func (plainHandler) Forbid(*auth.Properties) error                                     { return nil }

// TestMiddlewareRequestHandlerDispatch covers the callback dispatch: a scheme
// marked as a request handler is enumerated after the default authenticate
// pass, resolved through the request scope, and driven when it owns the
// request; a handled request short-circuits the pipeline, everything else
// passes through, and a resolution or processing failure warns without
// failing the request.
func TestMiddlewareRequestHandlerDispatch(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		registerScheme  bool // register the "ext" request-handler scheme
		registerFactory bool // provide a factory for it (false => resolution error)
		nonConforming   bool // factory yields a handler missing auth.RequestHandler
		should          bool
		handled         bool
		handleErr       error
		failurePath     string // middleware failure-redirect path ("" => 500)
		wantNextCalled  bool
		wantHandleCalls int
		wantStatus      int    // asserted only when non-zero
		wantLocation    string // redirect Location; asserted only when non-empty
		wantWarn        bool
	}{
		"handled short-circuits": {
			registerScheme: true, registerFactory: true, should: true, handled: true,
			wantNextCalled: false, wantHandleCalls: 1, wantStatus: http.StatusFound,
		},
		"not owned passes through": {
			registerScheme: true, registerFactory: true, should: false,
			wantNextCalled: true, wantHandleCalls: 0,
		},
		"resolution error passes through and warns": {
			registerScheme: true, registerFactory: false,
			wantNextCalled: true, wantHandleCalls: 0, wantWarn: true,
		},
		"non-conforming handler passes through and warns": {
			registerScheme: true, registerFactory: true, nonConforming: true,
			wantNextCalled: true, wantHandleCalls: 0, wantWarn: true,
		},
		"no request-handler scheme passes through": {
			registerScheme: false, registerFactory: false,
			wantNextCalled: true, wantHandleCalls: 0,
		},
		// A leg that owns the request but errors before writing terminates
		// the request. With no failure path configured the terminal response
		// is a 500, never a fall-through to the downstream 404.
		"processing error without handling writes 500 and warns": {
			registerScheme: true, registerFactory: true, should: true,
			handleErr:      errors.New("token exchange failed"),
			wantNextCalled: false, wantHandleCalls: 1, wantStatus: http.StatusInternalServerError, wantWarn: true,
		},
		// The same failure with a configured path redirects there carrying the
		// neutral error code instead of writing a 500.
		"processing error without handling redirects to configured failure path": {
			registerScheme: true, registerFactory: true, should: true,
			handleErr:      errors.New("token exchange failed"),
			failurePath:    "/account/login-failed",
			wantNextCalled: false, wantHandleCalls: 1, wantStatus: http.StatusFound,
			wantLocation: "/account/login-failed?error=" + auth.ExternalLoginFailedError, wantWarn: true,
		},
		// A handled leg already wrote its response, so a post-write error must
		// not be written over — the handler's status stands even with a path
		// configured.
		"processing error while handled warns and still short-circuits": {
			registerScheme: true, registerFactory: true, should: true, handled: true,
			handleErr: errors.New("post-write failure"), failurePath: "/account/login-failed",
			wantNextCalled: false, wantHandleCalls: 1, wantStatus: http.StatusFound, wantWarn: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			schemes := NewSchemeProvider(auth.NewOptions())
			provider := newKeyedProvider()
			spy := &requestHandlerSpy{should: tc.should, handled: tc.handled, handleErr: tc.handleErr}
			if tc.registerScheme {
				if err := schemes.AddScheme(auth.NewRequestHandlerScheme("ext", "handler")); err != nil {
					t.Fatalf("AddScheme: %v", err)
				}
			} else {
				// A plain scheme must NOT be enumerated by GetRequestHandlerSchemes.
				if err := schemes.AddScheme(auth.NewScheme("plain", "handler")); err != nil {
					t.Fatalf("AddScheme: %v", err)
				}
			}
			if tc.registerFactory {
				if tc.nonConforming {
					provider.factories["ext"] = func() auth.Handler { return plainHandler{} }
				} else {
					provider.factories["ext"] = func() auth.Handler { return spy }
				}
			}
			handlers := NewHandlerProvider(schemes, provider)
			provider.services[reflect.TypeFor[auth.HandlerProvider]()] = auth.HandlerProvider(handlers)

			nextCalled := false
			downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			middleware := Middleware(schemes, logger, tc.failurePath)
			request := httptest.NewRequest(http.MethodGet, "/signin-ext", nil)
			request = request.WithContext(hosting.ContextWithScope(request.Context(), provider))
			response := httptest.NewRecorder()

			middleware(downstream).ServeHTTP(response, request)

			require.Equal(t, tc.wantNextCalled, nextCalled, "downstream reach")
			require.Equal(t, tc.wantHandleCalls, spy.handleCalls, "HandleRequest calls")
			if tc.wantStatus != 0 {
				require.Equal(t, tc.wantStatus, response.Code, "handler-written status")
			}
			if tc.wantLocation != "" {
				require.Equal(t, tc.wantLocation, response.Header().Get("Location"), "failure redirect Location")
			}
			if tc.wantWarn {
				require.Contains(t, strings.ToLower(logBuf.String()), "warn", "expected a warning log")
			} else {
				require.Zero(t, logBuf.Len(), "unexpected log output: %s", logBuf.String())
			}
		})
	}
}

// signCaptureHandler records sign-in and sign-out invocations so a test can
// assert the service routed to it.
type signCaptureHandler struct {
	signedIn  bool
	signedOut bool
}

func (h *signCaptureHandler) Initialize(*http.Request, http.ResponseWriter, *auth.Scheme) error {
	return nil
}
func (h *signCaptureHandler) Authenticate() (*auth.Result, error) { return auth.NoResult(), nil }
func (h *signCaptureHandler) Challenge(*auth.Properties) error    { return nil }
func (h *signCaptureHandler) Forbid(*auth.Properties) error       { return nil }
func (h *signCaptureHandler) SignIn(*claims.ClaimsPrincipal, *auth.Properties) error {
	h.signedIn = true
	return nil
}
func (h *signCaptureHandler) SignOut(*auth.Properties) error { h.signedOut = true; return nil }

// TestServiceEmptySchemeResolvesToDefault verifies that sign-in and sign-out with
// an empty scheme resolve to the configured default sign-in / sign-out scheme
// rather than no-op. Callers that sign the app in after an external login pass an
// empty scheme expecting the default cookie handler to receive it.
func TestServiceEmptySchemeResolvesToDefault(t *testing.T) {
	t.Parallel()

	options := auth.NewOptions()
	options.DefaultSignInScheme = "appcookie"
	options.DefaultSignOutScheme = "appcookie"
	schemes := NewSchemeProvider(options)
	if err := schemes.AddScheme(auth.NewScheme("appcookie", "cookie")); err != nil {
		t.Fatalf("AddScheme: %v", err)
	}

	spy := &signCaptureHandler{}
	provider := newKeyedProvider()
	provider.factories["appcookie"] = func() auth.Handler { return spy }
	service := NewService(schemes, NewHandlerProvider(schemes, provider))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	require.NoError(t, service.SignIn(r, w, "", claims.NewClaimsPrincipal(), auth.NewProperties()))
	require.True(t, spy.signedIn, "empty sign-in scheme must resolve to the default sign-in scheme")

	require.NoError(t, service.SignOut(r, w, "", auth.NewProperties()))
	require.True(t, spy.signedOut, "empty sign-out scheme must resolve to the default sign-out scheme")
}
