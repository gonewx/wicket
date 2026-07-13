// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package google_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/auth/google"
	"github.com/gonewx/wicket/auth/oauth"
	claimspkg "github.com/gonewx/wicket/claims"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGoogleCreateTicketUsesOptionsUserInformationEndpoint guards that CreateTicket
// requests the configured UserInformationEndpoint rather than a fixed default, so
// an injected mock, regional, or proxied endpoint is honored. The backchannel
// transport rewrites only scheme and host and preserves the path, so the path the
// mock receives reveals which endpoint the handler chose.
func TestGoogleCreateTicketUsesOptionsUserInformationEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body, _ := json.Marshal(map[string]any{"id": "u1"})
		_, _ = w.Write(body)
	}))
	defer mockGoogle.Close()

	opts := newTestOptions(func(o *google.Options) {
		o.SetUserInformationEndpoint(mockGoogle.URL + "/sentinel-userinfo")
		o.SetBackchannelHttpHandler(mockTransport(mockGoogle.URL))
	})
	h := newTestHandler(opts)
	initHandler(t, h)

	identity := claimspkg.NewClaimsIdentity(claimspkg.WithAuthenticationType("Google"))
	_, err := h.CreateTicket(identity, auth.NewProperties(), &oauth.TokenResponse{AccessToken: "t", TokenType: "Bearer"})
	require.NoError(t, err)
	assert.Equal(t, "/sentinel-userinfo", gotPath,
		"CreateTicket must request the configured UserInformationEndpoint path, not the hardcoded constant")
}
