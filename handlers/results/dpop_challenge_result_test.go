// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonewx/wicket"
)

func TestDPoPChallengeResultOnTheWire(t *testing.T) {
	t.Parallel()
	algorithms := []string{"ES256", "PS256"}
	cases := map[string]struct {
		err         error
		description string
		algorithms  []string
		wantStatus  int
		wantHeader  string
	}{
		"invalid proof": {
			err: wicket.TokenErrorsInvalidDPoPProof, algorithms: algorithms, wantStatus: http.StatusUnauthorized,
			wantHeader: `DPoP error="invalid_dpop_proof", algs="ES256 PS256"`,
		},
		"invalid token": {
			err: wicket.ProtectedResourceErrorsInvalidToken, algorithms: algorithms, wantStatus: http.StatusUnauthorized,
			wantHeader: `DPoP error="invalid_token", algs="ES256 PS256"`,
		},
		"nil error stands for invalid token": {
			algorithms: algorithms, wantStatus: http.StatusUnauthorized,
			wantHeader: `DPoP error="invalid_token", algs="ES256 PS256"`,
		},
		"expired token": {
			err: wicket.ProtectedResourceErrorsExpiredToken, description: "ignored", algorithms: algorithms, wantStatus: http.StatusUnauthorized,
			wantHeader: `DPoP error="invalid_token", error_description="The access token expired", algs="ES256 PS256"`,
		},
		"invalid request": {
			err: wicket.ProtectedResourceErrorsInvalidRequest, algorithms: algorithms, wantStatus: http.StatusBadRequest,
			wantHeader: `DPoP error="invalid_request", algs="ES256 PS256"`,
		},
		"insufficient scope with description": {
			err: wicket.ProtectedResourceErrorsInsufficientScope, description: `needs "openid"`, algorithms: algorithms, wantStatus: http.StatusForbidden,
			wantHeader: `DPoP error="insufficient_scope", error_description="needs \"openid\"", algs="ES256 PS256"`,
		},
		"unlisted error": {
			err: errors.New("other_error"), algorithms: []string{"ES256"}, wantStatus: http.StatusUnauthorized,
			wantHeader: `DPoP error="other_error", algs="ES256"`,
		},
		"no algorithms": {
			err: wicket.ProtectedResourceErrorsInvalidToken, wantStatus: http.StatusUnauthorized,
			wantHeader: `DPoP error="invalid_token"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := NewDPoPChallengeResult(tc.err, tc.description, tc.algorithms).Execute(w, r); err != nil {
					t.Errorf("Execute: %v", err)
				}
			}))
			defer server.Close()

			response, err := http.Get(server.URL)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if response.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode, tc.wantStatus)
			}
			if got := response.Header.Values("WWW-Authenticate"); len(got) != 1 || got[0] != tc.wantHeader {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, tc.wantHeader)
			}
			if got := response.Header.Values("Cache-Control"); len(got) != 1 || got[0] != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if len(body) != 0 {
				t.Fatalf("body = %q, want none", body)
			}
		})
	}
}
