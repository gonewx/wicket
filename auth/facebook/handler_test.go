// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package facebook_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	gois "github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authevents "github.com/gonewx/wicket/auth/core/events"
	"github.com/gonewx/wicket/auth/facebook"
	"github.com/gonewx/wicket/auth/oauth"
	oauthcore "github.com/gonewx/wicket/auth/oauth/core"
	claimspkg "github.com/gonewx/wicket/claims"
	svcimpl "github.com/gonewx/wicket/services/impl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staticOptionsMonitor struct {
	opts *facebook.Options
}

func (m *staticOptionsMonitor) CurrentValue() (*facebook.Options, error) {
	return m.opts, nil
}

func (m *staticOptionsMonitor) Get(_ string) (*facebook.Options, error) {
	return m.opts, nil
}

func newTestOptions(configure func(*facebook.Options)) *facebook.Options {
	opts := facebook.NewOptions()
	opts.SetAppId("test-app-id")
	opts.SetAppSecret("test-app-secret")

	dpProvider := svcimpl.NewDataProtectionProvider()
	pc := oauthcore.NewPostConfigureOptions[*facebook.Options](dpProvider)
	if configure != nil {
		configure(opts)
	}
	_ = pc.PostConfigure("Facebook", opts)
	return opts
}

func newTestHandler(opts *facebook.Options) *facebook.Handler {
	mon := &staticOptionsMonitor{opts: opts}
	logger := slog.Default()
	clock := svcimpl.SystemClock{}
	return facebook.NewHandler(mon, logger, clock)
}

func initHandler(t *testing.T, h *facebook.Handler) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://testhost/challenge", nil)
	w := httptest.NewRecorder()
	scheme := &auth.Scheme{Name: "Facebook", HandlerType: "FacebookHandler"}
	err := h.Initialize(req, w, scheme)
	require.NoError(t, err)
	return req, w
}

func TestFacebookOptionsDefaults(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		check func(*testing.T, *facebook.Options)
	}{
		"callback path is /signin-facebook": {
			check: func(t *testing.T, o *facebook.Options) {
				assert.Equal(t, "/signin-facebook", o.CallbackPath())
			},
		},
		"authorization endpoint is Facebook dialog": {
			check: func(t *testing.T, o *facebook.Options) {
				assert.Equal(t, "https://www.facebook.com/v11.0/dialog/oauth", o.AuthorizationEndpoint())
			},
		},
		"token endpoint is Facebook graph": {
			check: func(t *testing.T, o *facebook.Options) {
				assert.Equal(t, "https://graph.facebook.com/v11.0/oauth/access_token", o.TokenEndpoint())
			},
		},
		"userinfo endpoint is Facebook graph me": {
			check: func(t *testing.T, o *facebook.Options) {
				assert.Equal(t, "https://graph.facebook.com/v11.0/me", o.UserInformationEndpoint())
			},
		},
		"default scope is email only": {
			check: func(t *testing.T, o *facebook.Options) {
				assert.Equal(t, []string{"email"}, o.Scope())
			},
		},
		"appsecret_proof enabled by default": {
			check: func(t *testing.T, o *facebook.Options) {
				assert.True(t, o.SendAppSecretProof)
			},
		},
		"has fourteen claim actions": {
			check: func(t *testing.T, o *facebook.Options) {
				assert.Len(t, o.ClaimActions(), 14)
			},
		},
		"default fields are name email first_name last_name": {
			check: func(t *testing.T, o *facebook.Options) {
				assert.Equal(t, []string{"name", "email", "first_name", "last_name"}, o.Fields())
			},
		},
		"New factory creates valid instance": {
			check: func(t *testing.T, o *facebook.Options) {
				fresh := o.New()
				require.NotNil(t, fresh)
				assert.Equal(t, "/signin-facebook", fresh.CallbackPath())
				assert.True(t, fresh.SendAppSecretProof)
			},
		},
		"authentication scheme constant matches": {
			check: func(t *testing.T, _ *facebook.Options) {
				assert.Equal(t, "Facebook", facebook.AuthenticationScheme)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := facebook.NewOptions()
			tc.check(t, opts)
		})
	}
}

func TestFacebookDefaultConstants(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		got  string
		want string
	}{
		"display name": {
			got: facebook.DisplayName, want: "Facebook",
		},
		"authorization endpoint": {
			got: facebook.AuthorizationEndpoint, want: "https://www.facebook.com/v11.0/dialog/oauth",
		},
		"token endpoint": {
			got: facebook.TokenEndpoint, want: "https://graph.facebook.com/v11.0/oauth/access_token",
		},
		"userinfo endpoint": {
			got: facebook.UserInformationEndpoint, want: "https://graph.facebook.com/v11.0/me",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.got)
		})
	}
}

func TestFacebookOptionsValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure       func(*facebook.Options)
		wantErr         bool
		wantErrContains string
	}{
		"missing AppId fails with named argument error": {
			configure: func(o *facebook.Options) {
				o.SetAppSecret("secret-only")
			},
			wantErr:         true,
			wantErrContains: "AppId",
		},
		"blank AppId fails with named argument error": {
			configure: func(o *facebook.Options) {
				o.SetAppId("   ")
				o.SetAppSecret("secret-only")
			},
			wantErr:         true,
			wantErrContains: "AppId",
		},
		"missing AppSecret fails with named argument error": {
			configure: func(o *facebook.Options) {
				o.SetAppId("id-only")
			},
			wantErr:         true,
			wantErrContains: "AppSecret",
		},
		"both provided passes validation": {
			configure: func(o *facebook.Options) {
				o.SetAppId("id")
				o.SetAppSecret("secret")
			},
			wantErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := facebook.NewOptions()
			tc.configure(opts)
			err := opts.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, gois.ArgumentNullException)
				assert.Contains(t, err.Error(), tc.wantErrContains)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFacebookAppIdAliasing(t *testing.T) {
	t.Parallel()

	opts := facebook.NewOptions()
	opts.SetAppId("alias-app-id")
	opts.SetAppSecret("alias-app-secret")

	assert.Equal(t, "alias-app-id", opts.ClientId())
	assert.Equal(t, "alias-app-secret", opts.ClientSecret())

	opts.SetClientId("direct-client-id")
	opts.SetClientSecret("direct-client-secret")

	assert.Equal(t, "direct-client-id", opts.AppId())
	assert.Equal(t, "direct-client-secret", opts.AppSecret())
}

func TestFacebookAddFields(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		add  []string
		want []string
	}{
		"duplicate field is not appended": {
			add:  []string{"email"},
			want: []string{"name", "email", "first_name", "last_name"},
		},
		"new field is appended": {
			add:  []string{"birthday"},
			want: []string{"name", "email", "first_name", "last_name", "birthday"},
		},
		"mixed new and duplicate fields": {
			add:  []string{"name", "picture", "picture", "locale"},
			want: []string{"name", "email", "first_name", "last_name", "picture", "locale"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := facebook.NewOptions()
			opts.AddFields(tc.add...)
			assert.Equal(t, tc.want, opts.Fields())
		})
	}
}

func TestFacebookBuildChallengeUrl(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure    func(*facebook.Options)
		properties   func() *auth.Properties
		checkUrl     func(*testing.T, *url.URL)
		checkPresent map[string]string
		checkAbsent  []string
	}{
		"redirects to Facebook authorization endpoint": {
			properties: func() *auth.Properties { return auth.NewProperties() },
			checkUrl: func(t *testing.T, u *url.URL) {
				assert.Equal(t, "https", u.Scheme)
				assert.Equal(t, "www.facebook.com", u.Host)
				assert.Equal(t, "/v11.0/dialog/oauth", u.Path)
			},
		},
		"includes required parameters": {
			properties: func() *auth.Properties { return auth.NewProperties() },
			checkPresent: map[string]string{
				"response_type": "code",
				"client_id":     "test-app-id",
				"redirect_uri":  "http://testhost/signin-facebook",
			},
			checkUrl: func(t *testing.T, u *url.URL) {
				assert.NotEmpty(t, u.Query().Get("scope"))
				assert.NotEmpty(t, u.Query().Get("state"))
			},
		},
		"default scope is email": {
			properties: func() *auth.Properties { return auth.NewProperties() },
			checkPresent: map[string]string{
				"scope": "email",
			},
		},
		"configured scopes are space joined": {
			configure: func(o *facebook.Options) {
				o.ClearScope()
				o.AddScope("foo")
				o.AddScope("bar")
			},
			properties: func() *auth.Properties { return auth.NewProperties() },
			checkPresent: map[string]string{
				"scope": "foo bar",
			},
		},
		"challenge properties scope overrides configured scope": {
			configure: func(o *facebook.Options) {
				o.ClearScope()
				o.AddScope("foo")
				o.AddScope("bar")
			},
			properties: func() *auth.Properties {
				cp := oauth.NewChallengeProperties()
				cp.SetScope([]string{"baz", "qux"})
				return cp.Properties
			},
			checkPresent: map[string]string{
				"scope": "baz qux",
			},
		},
		"scope parameter on plain properties overrides configured scope": {
			properties: func() *auth.Properties {
				p := auth.NewProperties()
				p.SetParameter(oauth.ScopeKey, []string{"baz", "qux"})
				return p
			},
			checkPresent: map[string]string{
				"scope": "baz qux",
			},
		},
		"pkce disabled by default": {
			properties:  func() *auth.Properties { return auth.NewProperties() },
			checkAbsent: []string{"code_challenge", "code_challenge_method"},
		},
		"pkce enabled flows through base challenge path": {
			configure: func(o *facebook.Options) {
				o.SetUsePkce(true)
			},
			properties: func() *auth.Properties { return auth.NewProperties() },
			checkPresent: map[string]string{
				"code_challenge_method": "S256",
			},
			checkUrl: func(t *testing.T, u *url.URL) {
				assert.NotEmpty(t, u.Query().Get("code_challenge"))
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := newTestOptions(tc.configure)
			h := newTestHandler(opts)
			initHandler(t, h)

			challengeUrl, err := h.BuildChallengeUrl(tc.properties(), "http://testhost/signin-facebook")
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

func TestFacebookChallengeRedirectEvent(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		customEvent   bool
		checkLocation func(*testing.T, *url.URL)
	}{
		"default event redirects to Facebook authorize endpoint": {
			customEvent: false,
			checkLocation: func(t *testing.T, u *url.URL) {
				assert.Equal(t, "www.facebook.com", u.Host)
				assert.Equal(t, "/v11.0/dialog/oauth", u.Path)
				assert.Equal(t, "code", u.Query().Get("response_type"))
			},
		},
		"custom event replaces the redirect": {
			customEvent: true,
			checkLocation: func(t *testing.T, u *url.URL) {
				assert.Equal(t, "/error", u.Path)
				assert.Equal(t, "test", u.Query().Get("custom"))
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := newTestOptions(func(o *facebook.Options) {
				if tc.customEvent {
					evts := oauthcore.NewEvents[*facebook.Options]()
					evts.OnRedirectToAuthorizationEndpoint = func(ctx *authevents.RedirectContext[*facebook.Options]) error {
						http.Redirect(ctx.Response, ctx.Request, "/error?custom=test", http.StatusFound)
						return nil
					}
					o.SetEvents(evts)
				}
			})
			h := newTestHandler(opts)
			_, w := initHandler(t, h)

			err := h.HandleChallenge(auth.NewProperties())
			require.NoError(t, err)

			require.Equal(t, http.StatusFound, w.Code)
			location, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			tc.checkLocation(t, location)
		})
	}
}

func TestFacebookHandlerConstruction(t *testing.T) {
	t.Parallel()

	opts := newTestOptions(nil)
	h := newTestHandler(opts)
	initHandler(t, h)

	require.Same(t, opts, h.Options, "handler must resolve the exact options instance from the monitor")
	assert.Equal(t, "Facebook", h.Scheme.Name)
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

func TestFacebookCreateTicket(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		userinfoStatus  int
		userinfoPayload map[string]any
		wantErr         bool
		wantErrContains string
		checkTicket     func(*testing.T, *auth.Ticket)
	}{
		"maps Facebook userinfo claims correctly": {
			userinfoStatus: http.StatusOK,
			userinfoPayload: map[string]any{
				"id":          "fb-user-id",
				"name":        "Test Name",
				"first_name":  "Test First",
				"middle_name": "Test Middle",
				"last_name":   "Test Last",
				"email":       "test@example.com",
				"birthday":    "01/01/2000",
				"gender":      "female",
				"link":        "https://www.facebook.com/test",
				"locale":      "en_US",
				"timezone":    "-8",
				"age_range":   map[string]any{"min": "21", "max": "65"},
				"location":    map[string]any{"name": "Seattle, Washington"},
			},
			checkTicket: func(t *testing.T, ticket *auth.Ticket) {
				require.NotNil(t, ticket)
				require.NotNil(t, ticket.Principal)
				expected := map[string]string{
					claimspkg.NameIdentifier:     "fb-user-id",
					claimspkg.Name:               "Test Name",
					claimspkg.GivenName:          "Test First",
					"urn:facebook:middle_name":   "Test Middle",
					claimspkg.Surname:            "Test Last",
					claimspkg.Email:              "test@example.com",
					claimspkg.DateOfBirth:        "01/01/2000",
					claimspkg.Gender:             "female",
					"urn:facebook:link":          "https://www.facebook.com/test",
					claimspkg.Locality:           "en_US",
					"urn:facebook:timezone":      "-8",
					"urn:facebook:age_range_min": "21",
					"urn:facebook:age_range_max": "65",
					"urn:facebook:location":      "Seattle, Washington",
				}
				for claimType, wantValue := range expected {
					claim := ticket.Principal.FindFirst(claimType)
					require.NotNil(t, claim, "claim type %s not found", claimType)
					assert.Equal(t, wantValue, claim.Value, "claim type %s", claimType)
				}
			},
		},
		"numeric sub-key values are skipped by claim actions": {
			userinfoStatus: http.StatusOK,
			userinfoPayload: map[string]any{
				"id":        "fb-user-id",
				"age_range": map[string]any{"min": 21, "max": 65},
			},
			checkTicket: func(t *testing.T, ticket *auth.Ticket) {
				require.NotNil(t, ticket)
				assert.Nil(t, ticket.Principal.FindFirst("urn:facebook:age_range_min"))
				assert.Nil(t, ticket.Principal.FindFirst("urn:facebook:age_range_max"))
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
				assert.Equal(t, "Facebook", ticket.Scheme)
			},
		},
		"ticket has correct authentication scheme": {
			userinfoStatus: http.StatusOK,
			userinfoPayload: map[string]any{
				"id": "user-123",
			},
			checkTicket: func(t *testing.T, ticket *auth.Ticket) {
				require.NotNil(t, ticket)
				assert.Equal(t, "Facebook", ticket.Scheme)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mockFacebook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.userinfoStatus)
				body, _ := json.Marshal(tc.userinfoPayload)
				_, _ = w.Write(body)
			}))
			defer mockFacebook.Close()

			opts := newTestOptions(func(o *facebook.Options) {
				o.SetBackchannelHttpHandler(mockTransport(mockFacebook.URL))
			})

			h := newTestHandler(opts)
			initHandler(t, h)

			identity := claimspkg.NewClaimsIdentity(
				claimspkg.WithAuthenticationType("Facebook"),
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

func TestFacebookUserInfoRequestShape(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure    func(*facebook.Options)
		checkRequest func(*testing.T, *url.URL, http.Header)
	}{
		"access token travels as query parameter not bearer header": {
			checkRequest: func(t *testing.T, u *url.URL, headers http.Header) {
				assert.Equal(t, "test-token", u.Query().Get("access_token"))
				assert.Empty(t, headers.Get("Authorization"))
			},
		},
		"appsecret_proof sent by default": {
			checkRequest: func(t *testing.T, u *url.URL, _ http.Header) {
				assert.NotEmpty(t, u.Query().Get("appsecret_proof"))
			},
		},
		"appsecret_proof omitted when disabled": {
			configure: func(o *facebook.Options) {
				o.SendAppSecretProof = false
			},
			checkRequest: func(t *testing.T, u *url.URL, _ http.Header) {
				assert.False(t, u.Query().Has("appsecret_proof"))
			},
		},
		"fields joined with comma-space separator": {
			checkRequest: func(t *testing.T, u *url.URL, _ http.Header) {
				assert.Equal(t, "name, email, first_name, last_name", u.Query().Get("fields"))
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var gotURL *url.URL
			var gotHeader http.Header
			mockFacebook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotURL = r.URL
				gotHeader = r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				body, _ := json.Marshal(map[string]any{"id": "u1"})
				_, _ = w.Write(body)
			}))
			defer mockFacebook.Close()

			opts := newTestOptions(func(o *facebook.Options) {
				o.SetBackchannelHttpHandler(mockTransport(mockFacebook.URL))
				if tc.configure != nil {
					tc.configure(o)
				}
			})
			h := newTestHandler(opts)
			initHandler(t, h)

			identity := claimspkg.NewClaimsIdentity(claimspkg.WithAuthenticationType("Facebook"))
			tokens := &oauth.TokenResponse{AccessToken: "test-token", TokenType: "Bearer"}
			_, err := h.CreateTicket(identity, auth.NewProperties(), tokens)
			require.NoError(t, err)

			require.NotNil(t, gotURL)
			tc.checkRequest(t, gotURL, gotHeader)
		})
	}
}

func TestFacebookAppSecretProofDeterministic(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	proofs := make([]string, 0, 2)
	mockFacebook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proofs = append(proofs, r.URL.Query().Get("appsecret_proof"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body, _ := json.Marshal(map[string]any{"id": "u1"})
		_, _ = w.Write(body)
	}))
	defer mockFacebook.Close()

	opts := newTestOptions(func(o *facebook.Options) {
		o.SetBackchannelHttpHandler(mockTransport(mockFacebook.URL))
	})
	h := newTestHandler(opts)
	initHandler(t, h)

	identity := claimspkg.NewClaimsIdentity(claimspkg.WithAuthenticationType("Facebook"))
	tokens := &oauth.TokenResponse{AccessToken: "stable-token", TokenType: "Bearer"}
	_, err := h.CreateTicket(identity, auth.NewProperties(), tokens)
	require.NoError(t, err)
	_, err = h.CreateTicket(identity, auth.NewProperties(), tokens)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, proofs, 2)
	assert.NotEmpty(t, proofs[0])
	assert.Equal(t, proofs[0], proofs[1], "same token and secret must yield the same proof")
}

func TestFacebookCustomUserInfoEndpointPreservesQuery(t *testing.T) {
	t.Parallel()

	var gotURL *url.URL
	mockFacebook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body, _ := json.Marshal(map[string]any{"id": "u1", "name": "N"})
		_, _ = w.Write(body)
	}))
	defer mockFacebook.Close()

	opts := newTestOptions(func(o *facebook.Options) {
		o.SetUserInformationEndpoint("https://graph.facebook.com/me?fields=email,timezone,picture")
		o.SetBackchannelHttpHandler(mockTransport(mockFacebook.URL))
	})
	h := newTestHandler(opts)
	initHandler(t, h)

	identity := claimspkg.NewClaimsIdentity(claimspkg.WithAuthenticationType("Facebook"))
	tokens := &oauth.TokenResponse{AccessToken: "tok", TokenType: "Bearer"}
	_, err := h.CreateTicket(identity, auth.NewProperties(), tokens)
	require.NoError(t, err)

	require.NotNil(t, gotURL)
	assert.Equal(t, "/me", gotURL.Path)
	assert.Equal(t, "email,timezone,picture", gotURL.Query().Get("fields"))
	assert.True(t, gotURL.Query().Has("access_token"))
}

func TestFacebookStateRecoverableAndConsumedParamsExcluded(t *testing.T) {
	t.Parallel()

	opts := newTestOptions(nil)
	h := newTestHandler(opts)
	initHandler(t, h)

	p := auth.NewProperties()
	redirect := "/after-login"
	p.SetRedirectUri(&redirect)

	challengeUrl, err := h.BuildChallengeUrl(p, "http://testhost/signin-facebook")
	require.NoError(t, err)

	parsed, err := url.Parse(challengeUrl)
	require.NoError(t, err)

	stateStr := parsed.Query().Get("state")
	require.NotEmpty(t, stateStr)

	stateProps := opts.StateDataFormat().Unprotect(stateStr)
	require.NotNil(t, stateProps, "state must round-trip through Unprotect")
	require.NotNil(t, stateProps.RedirectUri())
	assert.Equal(t, "/after-login", *stateProps.RedirectUri())
	assert.NotContains(t, stateProps.Items, oauth.ScopeKey)
}
