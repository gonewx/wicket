// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package google_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/auth/google"
	"github.com/gonewx/wicket/auth/oauth"
	oauthcore "github.com/gonewx/wicket/auth/oauth/core"
	claimspkg "github.com/gonewx/wicket/claims"
	svcimpl "github.com/gonewx/wicket/services/impl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staticOptionsMonitor struct {
	opts *google.Options
}

func (m *staticOptionsMonitor) CurrentValue() (*google.Options, error) {
	return m.opts, nil
}

func (m *staticOptionsMonitor) Get(_ string) (*google.Options, error) {
	return m.opts, nil
}

func newTestOptions(configure func(*google.Options)) *google.Options {
	opts := google.NewOptions()
	opts.SetClientId("test-client-id")
	opts.SetClientSecret("test-client-secret")

	dpProvider := svcimpl.NewDataProtectionProvider()
	pc := oauthcore.NewPostConfigureOptions[*google.Options](dpProvider)
	if configure != nil {
		configure(opts)
	}
	_ = pc.PostConfigure("Google", opts)
	return opts
}

func newTestHandler(opts *google.Options) *google.Handler {
	mon := &staticOptionsMonitor{opts: opts}
	logger := slog.Default()
	clock := svcimpl.SystemClock{}
	return google.NewHandler(mon, logger, clock)
}

func initHandler(t *testing.T, h *google.Handler) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://testhost/challenge", nil)
	w := httptest.NewRecorder()
	scheme := &auth.Scheme{Name: "Google", HandlerType: "GoogleHandler"}
	err := h.Initialize(req, w, scheme)
	require.NoError(t, err)
}

func TestGoogleOptionsDefaults(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		check func(*testing.T, *google.Options)
	}{
		"callback path is /signin-google": {
			check: func(t *testing.T, o *google.Options) {
				assert.Equal(t, "/signin-google", o.CallbackPath())
			},
		},
		"authorization endpoint is Google OAuth2": {
			check: func(t *testing.T, o *google.Options) {
				assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth", o.AuthorizationEndpoint())
			},
		},
		"token endpoint is Google OAuth2": {
			check: func(t *testing.T, o *google.Options) {
				assert.Equal(t, "https://oauth2.googleapis.com/token", o.TokenEndpoint())
			},
		},
		"userinfo endpoint is Google API v2": {
			check: func(t *testing.T, o *google.Options) {
				assert.Equal(t, "https://www.googleapis.com/oauth2/v2/userinfo", o.UserInformationEndpoint())
			},
		},
		"default scopes are openid profile email": {
			check: func(t *testing.T, o *google.Options) {
				scopes := o.Scope()
				assert.Equal(t, []string{"openid", "profile", "email"}, scopes)
			},
		},
		"has six claim actions": {
			check: func(t *testing.T, o *google.Options) {
				assert.Len(t, o.ClaimActions(), 6)
			},
		},
		"New factory creates valid instance": {
			check: func(t *testing.T, o *google.Options) {
				fresh := o.New()
				assert.NotNil(t, fresh)
				assert.Equal(t, "/signin-google", fresh.CallbackPath())
			},
		},
		"authentication scheme constant matches": {
			check: func(t *testing.T, _ *google.Options) {
				assert.Equal(t, "Google", google.AuthenticationScheme)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := google.NewOptions()
			tc.check(t, opts)
		})
	}
}

func TestGoogleChallengeProperties(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup func(*google.ChallengeProperties)
		check func(*testing.T, *google.ChallengeProperties)
	}{
		"access type round-trips": {
			setup: func(cp *google.ChallengeProperties) { cp.SetAccessType("offline") },
			check: func(t *testing.T, cp *google.ChallengeProperties) {
				assert.Equal(t, "offline", cp.AccessType())
			},
		},
		"approval prompt round-trips": {
			setup: func(cp *google.ChallengeProperties) { cp.SetApprovalPrompt("force") },
			check: func(t *testing.T, cp *google.ChallengeProperties) {
				assert.Equal(t, "force", cp.ApprovalPrompt())
			},
		},
		"include granted scopes round-trips": {
			setup: func(cp *google.ChallengeProperties) { cp.SetIncludeGrantedScopes(true) },
			check: func(t *testing.T, cp *google.ChallengeProperties) {
				assert.True(t, cp.IncludeGrantedScopes())
			},
		},
		"login hint round-trips": {
			setup: func(cp *google.ChallengeProperties) { cp.SetLoginHint("user@example.com") },
			check: func(t *testing.T, cp *google.ChallengeProperties) {
				assert.Equal(t, "user@example.com", cp.LoginHint())
			},
		},
		"prompt round-trips": {
			setup: func(cp *google.ChallengeProperties) { cp.SetPrompt("consent") },
			check: func(t *testing.T, cp *google.ChallengeProperties) {
				assert.Equal(t, "consent", cp.Prompt())
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cp := google.NewChallengeProperties()
			tc.setup(cp)
			tc.check(t, cp)
		})
	}
}

func TestGoogleBuildChallengeUrl(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure    func(*google.Options)
		properties   func() *auth.Properties
		redirectUri  string
		checkUrl     func(*testing.T, *url.URL)
		checkAbsent  []string
		checkPresent map[string]string
	}{
		"redirects to Google authorization endpoint": {
			configure:   nil,
			properties:  func() *auth.Properties { return auth.NewProperties() },
			redirectUri: "http://testhost/signin-google",
			checkUrl: func(t *testing.T, u *url.URL) {
				u.RawQuery = ""
				assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth", u.String())
			},
		},
		"includes required parameters": {
			configure:   nil,
			properties:  func() *auth.Properties { return auth.NewProperties() },
			redirectUri: "http://testhost/signin-google",
			checkPresent: map[string]string{
				"response_type": "code",
				"client_id":     "test-client-id",
				"redirect_uri":  "http://testhost/signin-google",
			},
			checkUrl: func(t *testing.T, u *url.URL) {
				q := u.Query()
				assert.NotEmpty(t, q.Get("scope"))
				assert.NotEmpty(t, q.Get("state"))
			},
		},
		"default scope is openid profile email": {
			configure:   nil,
			properties:  func() *auth.Properties { return auth.NewProperties() },
			redirectUri: "http://testhost/signin-google",
			checkPresent: map[string]string{
				"scope": "openid profile email",
			},
		},
		"omits optional params by default": {
			configure:   nil,
			properties:  func() *auth.Properties { return auth.NewProperties() },
			redirectUri: "http://testhost/signin-google",
			checkAbsent: []string{"access_type", "prompt", "approval_prompt", "login_hint", "include_granted_scopes"},
		},
		"includes access_type from options": {
			configure: func(o *google.Options) {
				at := "offline"
				o.AccessType = &at
			},
			properties:  func() *auth.Properties { return auth.NewProperties() },
			redirectUri: "http://testhost/signin-google",
			checkPresent: map[string]string{
				"access_type": "offline",
			},
		},
		"challenge properties params map to URL query args": {
			configure: nil,
			properties: func() *auth.Properties {
				cp := google.NewChallengeProperties()
				cp.SetAccessType("offline")
				cp.SetApprovalPrompt("force")
				cp.SetPrompt("consent")
				cp.SetLoginHint("test@example.com")
				cp.SetIncludeGrantedScopes(false)
				return cp.Properties
			},
			redirectUri: "http://testhost/signin-google",
			checkPresent: map[string]string{
				"access_type":           "offline",
				"approval_prompt":       "force",
				"prompt":                "consent",
				"login_hint":            "test@example.com",
				"include_granted_scopes": "false",
			},
		},
		"items params map to URL query args": {
			configure: nil,
			properties: func() *auth.Properties {
				p := auth.NewProperties()
				p.Items["access_type"] = "offline"
				p.Items["approval_prompt"] = "force"
				p.Items["prompt"] = "consent"
				p.Items["login_hint"] = "test@example.com"
				p.Items["include_granted_scopes"] = "false"
				return p
			},
			redirectUri: "http://testhost/signin-google",
			checkPresent: map[string]string{
				"access_type":           "offline",
				"approval_prompt":       "force",
				"prompt":                "consent",
				"login_hint":            "test@example.com",
				"include_granted_scopes": "false",
			},
		},
		"typed parameters override items": {
			configure: nil,
			properties: func() *auth.Properties {
				cp := google.NewChallengeProperties()
				cp.Items["prompt"] = "select_account"
				cp.Items["login_hint"] = "old@example.com"
				cp.SetPrompt("consent")
				cp.SetLoginHint("new@example.com")
				return cp.Properties
			},
			redirectUri: "http://testhost/signin-google",
			checkPresent: map[string]string{
				"prompt":     "consent",
				"login_hint": "new@example.com",
			},
		},
		"custom scope from properties overrides default": {
			configure: nil,
			properties: func() *auth.Properties {
				cp := google.NewChallengeProperties()
				cp.SetScope([]string{"openid", "https://www.googleapis.com/auth/plus.login"})
				return cp.Properties
			},
			redirectUri: "http://testhost/signin-google",
			checkPresent: map[string]string{
				"scope": "openid https://www.googleapis.com/auth/plus.login",
			},
		},
		"properties items consumed and not serialized into state": {
			configure: nil,
			properties: func() *auth.Properties {
				p := auth.NewProperties()
				p.Items["access_type"] = "offline"
				p.Items["prompt"] = "consent"
				return p
			},
			redirectUri: "http://testhost/signin-google",
			checkUrl: func(t *testing.T, u *url.URL) {
				assert.Equal(t, "offline", u.Query().Get("access_type"))
				assert.Equal(t, "consent", u.Query().Get("prompt"))
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := newTestOptions(tc.configure)
			h := newTestHandler(opts)
			initHandler(t, h)

			challengeUrl, err := h.BuildChallengeUrl(tc.properties(), tc.redirectUri)
			require.NoError(t, err)

			parsed, err := url.Parse(challengeUrl)
			require.NoError(t, err)

			if tc.checkUrl != nil {
				tc.checkUrl(t, parsed)
			}
			for param, expected := range tc.checkPresent {
				assert.Equal(t, expected, parsed.Query().Get(param), "param %s", param)
			}
			for _, absent := range tc.checkAbsent {
				assert.False(t, parsed.Query().Has(absent), "param %s should be absent", absent)
			}
		})
	}
}

func TestGoogleCreateTicket(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		userinfoStatus  int
		userinfoPayload map[string]any
		wantErr         bool
		wantErrContains string
		checkTicket     func(*testing.T, *auth.Ticket)
	}{
		"maps Google userinfo claims correctly": {
			userinfoStatus: http.StatusOK,
			userinfoPayload: map[string]any{
				"id":          "test-user-id",
				"name":        "Test Name",
				"given_name":  "Test Given",
				"family_name": "Test Family",
				"link":        "https://plus.google.com/test",
				"email":       "test@example.com",
			},
			checkTicket: func(t *testing.T, ticket *auth.Ticket) {
				require.NotNil(t, ticket)
				require.NotNil(t, ticket.Principal)
				claims := ticket.Principal.Claims()
				findClaim := func(ct string) string {
					for _, c := range claims {
						if c.Type == ct {
							s, _ := c.Value.(string)
							return s
						}
					}
					return ""
				}
				assert.Equal(t, "test-user-id", findClaim(claimspkg.NameIdentifier))
				assert.Equal(t, "Test Name", findClaim(claimspkg.Name))
				assert.Equal(t, "Test Given", findClaim(claimspkg.GivenName))
				assert.Equal(t, "Test Family", findClaim(claimspkg.Surname))
				assert.Equal(t, "test@example.com", findClaim(claimspkg.Email))
				assert.Equal(t, "https://plus.google.com/test", findClaim("urn:google:profile"))
			},
		},
		"returns error on non-200 userinfo response": {
			userinfoStatus:  http.StatusUnauthorized,
			userinfoPayload: map[string]any{"error": "invalid_token"},
			wantErr:         true,
			wantErrContains: "401",
		},
		"returns error on server error from userinfo": {
			userinfoStatus:  http.StatusInternalServerError,
			userinfoPayload: map[string]any{},
			wantErr:         true,
			wantErrContains: "500",
		},
		"handles empty userinfo gracefully": {
			userinfoStatus:  http.StatusOK,
			userinfoPayload: map[string]any{},
			checkTicket: func(t *testing.T, ticket *auth.Ticket) {
				require.NotNil(t, ticket)
				assert.Equal(t, "Google", ticket.Scheme)
			},
		},
		"ticket has correct authentication scheme": {
			userinfoStatus: http.StatusOK,
			userinfoPayload: map[string]any{
				"id": "user-123",
			},
			checkTicket: func(t *testing.T, ticket *auth.Ticket) {
				require.NotNil(t, ticket)
				assert.Equal(t, "Google", ticket.Scheme)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.userinfoStatus)
				body, _ := json.Marshal(tc.userinfoPayload)
				_, _ = w.Write(body)
			}))
			defer mockGoogle.Close()

			opts := newTestOptions(func(o *google.Options) {
				o.SetBackchannelHttpHandler(mockTransport(mockGoogle.URL))
			})

			h := newTestHandler(opts)
			initHandler(t, h)

			identity := claimspkg.NewClaimsIdentity(
				claimspkg.WithAuthenticationType("Google"),
			)
			props := auth.NewProperties()
			tokens := &oauth.TokenResponse{AccessToken: "test-token", TokenType: "Bearer"}

			ticket, err := h.CreateTicket(identity, props, tokens)
			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(t, err)
			if tc.checkTicket != nil {
				tc.checkTicket(t, ticket)
			}
		})
	}
}

func TestGoogleHandlerConstruction(t *testing.T) {
	t.Parallel()

	opts := newTestOptions(nil)
	h := newTestHandler(opts)
	assert.NotNil(t, h)
	assert.NotNil(t, h.Handler)
}

type mockTransportFunc func(req *http.Request) (*http.Response, error)

func (f mockTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func mockTransport(mockURL string) http.RoundTripper {
	parsed, _ := url.Parse(mockURL)
	return mockTransportFunc(func(req *http.Request) (*http.Response, error) {
		proxyReq := req.Clone(req.Context())
		proxyReq.URL.Scheme = parsed.Scheme
		proxyReq.URL.Host = parsed.Host
		return http.DefaultTransport.RoundTrip(proxyReq)
	})
}

func TestGoogleCreateTicketBearerTokenSent(t *testing.T) {
	t.Parallel()

	var receivedAuth string
	mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body, _ := json.Marshal(map[string]any{"id": "u1"})
		_, _ = w.Write(body)
	}))
	defer mockGoogle.Close()

	opts := newTestOptions(func(o *google.Options) {
		o.SetBackchannelHttpHandler(mockTransport(mockGoogle.URL))
	})
	h := newTestHandler(opts)
	initHandler(t, h)

	identity := claimspkg.NewClaimsIdentity(claimspkg.WithAuthenticationType("Google"))
	tokens := &oauth.TokenResponse{AccessToken: "my-access-token", TokenType: "Bearer"}
	_, err := h.CreateTicket(identity, auth.NewProperties(), tokens)
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-access-token", receivedAuth)
}

func TestGoogleDefaultConstants(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		got  string
		want string
	}{
		"display name": {
			got: google.DisplayName, want: "Google",
		},
		"authorization endpoint": {
			got: google.AuthorizationEndpoint, want: "https://accounts.google.com/o/oauth2/v2/auth",
		},
		"token endpoint": {
			got: google.TokenEndpoint, want: "https://oauth2.googleapis.com/token",
		},
		"userinfo endpoint": {
			got: google.UserInformationEndpoint, want: "https://www.googleapis.com/oauth2/v2/userinfo",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.got)
		})
	}
}

func TestGoogleBuildChallengeUrlStateNotContainConsumedParams(t *testing.T) {
	t.Parallel()

	opts := newTestOptions(nil)
	h := newTestHandler(opts)
	initHandler(t, h)

	p := auth.NewProperties()
	p.Items["access_type"] = "offline"
	p.Items["prompt"] = "consent"
	p.Items["login_hint"] = "user@test.com"

	challengeUrl, err := h.BuildChallengeUrl(p, "http://testhost/signin-google")
	require.NoError(t, err)

	parsed, err := url.Parse(challengeUrl)
	require.NoError(t, err)

	assert.Equal(t, "offline", parsed.Query().Get("access_type"))
	assert.Equal(t, "consent", parsed.Query().Get("prompt"))

	stateStr := parsed.Query().Get("state")
	assert.NotEmpty(t, stateStr)

	stateProps := opts.StateDataFormat().Unprotect(stateStr)
	if stateProps != nil {
		assert.NotContains(t, stateProps.Items, "access_type")
		assert.NotContains(t, stateProps.Items, "prompt")
		assert.NotContains(t, stateProps.Items, "login_hint")
	}
}

func TestGoogleClaimActionsMappings(t *testing.T) {
	t.Parallel()

	mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body, _ := json.Marshal(map[string]any{
			"id":          "uid-42",
			"name":        "Jane Doe",
			"given_name":  "Jane",
			"family_name": "Doe",
			"link":        "https://profiles.google.com/jane",
			"email":       "jane@example.com",
		})
		_, _ = w.Write(body)
	}))
	defer mockGoogle.Close()

	expected := map[string]string{
		claimspkg.NameIdentifier: "uid-42",
		claimspkg.Name:           "Jane Doe",
		claimspkg.GivenName:      "Jane",
		claimspkg.Surname:        "Doe",
		"urn:google:profile":     "https://profiles.google.com/jane",
		claimspkg.Email:          "jane@example.com",
	}

	opts := newTestOptions(func(o *google.Options) {
		o.SetBackchannelHttpHandler(mockTransport(mockGoogle.URL))
	})
	h := newTestHandler(opts)
	initHandler(t, h)

	identity := claimspkg.NewClaimsIdentity(claimspkg.WithAuthenticationType("Google"))
	tokens := &oauth.TokenResponse{AccessToken: "tok", TokenType: "Bearer"}
	ticket, err := h.CreateTicket(identity, auth.NewProperties(), tokens)
	require.NoError(t, err)

	for claimType, wantValue := range expected {
		t.Run(strings.ReplaceAll(claimType, "/", "_"), func(t *testing.T) {
			claim := ticket.Principal.FindFirst(claimType)
			require.NotNil(t, claim, "claim type %s not found", claimType)
			assert.Equal(t, wantValue, claim.Value)
		})
	}
}
