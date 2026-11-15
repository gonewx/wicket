// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package authorize

import (
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

const (
	createClientId    = "create-client"
	createRedirectUri = "https://create-client.example/callback"
	createSubject     = "create-subject"
	accountCreation   = "/custom"
)

// newPromptCreatePipeline builds a pipeline with one authorization code
// client; configured declares the account creation page.
func newPromptCreatePipeline(t *testing.T, configured bool) *integration_common.WicketPipeline {
	t.Helper()
	client := storage_models.NewClient()
	client.ClientId = createClientId
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.RequireConsent = false
	client.RedirectUris = []string{createRedirectUri}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId}
	require.NoError(t, client.SetAllowedGrantTypes(wicket.GrantTypesCode))

	p := integration_common.NewWicketPipeline()
	p.Clients = []*storage_models.Client{client}
	p.IdentityScopes = []*storage_models.IdentityResource{storage_models.IdentityResourcesOpenId()}
	user := test.NewTestUser()
	user.SubjectId = createSubject
	user.Username = createSubject
	p.Users = []*test.TestUser{user}
	if configured {
		p.Root.ServerConfig().SetAccountCreationUrl(accountCreation)
	}
	p.Initialize()
	t.Cleanup(p.TestServer.Close)
	p.BrowserClient.AllowAutoRedirect = false
	return p
}

// browsePromptCreate requests target without following redirects and
// returns the status and the absolute redirect target.
func browsePromptCreate(t *testing.T, p *integration_common.WicketPipeline, target string) (int, *url.URL) {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = p.TestServer.URL + target
	}
	resp, err := p.BrowserClient.Get(target)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	location := resp.Header.Get("Location")
	if strings.HasPrefix(location, "/") {
		location = p.TestServer.URL + location
	}
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	return resp.StatusCode, parsed
}

func authorizeWithPrompt(t *testing.T, p *integration_common.WicketPipeline, prompt string) (int, *url.URL) {
	t.Helper()
	u, err := p.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     createClientId,
		ResponseType: wicket.ResponseTypesCode,
		Scope:        wicket.StandardScopesOpenId,
		RedirectUri:  createRedirectUri,
		State:        "create-state",
		Nonce:        "create-nonce",
		Extra:        url.Values{wicket.AuthorizeRequestPrompt: {prompt}},
	})
	require.NoError(t, err)
	return browsePromptCreate(t, p, u.String())
}

func isRedirectStatus(status int) bool {
	return status == http.StatusFound || status == http.StatusSeeOther
}

func pagePath(p *integration_common.WicketPipeline, location *url.URL) string {
	return strings.TrimPrefix(location.Path, strings.TrimSuffix(p.TestServer.URL, "/"))
}

// visitAccountCreation opens the account creation page the location points
// to, signs the user in as the page would and returns the return URL.
func visitAccountCreation(t *testing.T, p *integration_common.WicketPipeline, location *url.URL) string {
	t.Helper()
	a := require.New(t)
	a.Equal(accountCreation, location.Path, "redirect target %s", location)
	returnUrl := location.Query().Get(p.Options.UserInteraction.CustomRedirectReturnUrlParameter)
	a.NotEmpty(returnUrl)

	p.CustomWasCalled = false
	status, _ := browsePromptCreate(t, p, location.String())
	a.Equal(http.StatusOK, status)
	a.True(p.CustomWasCalled)
	a.NotNil(p.CustomRequest)
	a.True(slices.Contains(p.CustomRequest.PromptModes, wicket.PromptModesCreate), "PromptModes %v", p.CustomRequest.PromptModes)

	// The account creation page creates the account and signs the user in.
	a.NoError(p.Login(createSubject))
	p.LoginWasCalled = false
	return returnUrl
}

func requireCode(t *testing.T, location *url.URL) {
	t.Helper()
	require.True(t, strings.HasPrefix(location.String(), createRedirectUri), "location %s", location)
	require.NotEmpty(t, location.Query().Get("code"), "location %s", location)
	require.Empty(t, location.Query().Get("error"))
}

func TestPromptCreateRoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		prompt      string
		signedIn    bool
		wantConsent bool
	}{
		"anonymous":              {prompt: "create"},
		"signed in":              {prompt: "create", signedIn: true},
		"with login":             {prompt: "create login"},
		"with account selection": {prompt: "select_account create"},
		"with consent":           {prompt: "create consent", wantConsent: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)
			p := newPromptCreatePipeline(t, true)
			if tc.signedIn {
				a.NoError(p.Login(createSubject))
			}
			p.LoginWasCalled = false

			status, location := authorizeWithPrompt(t, p, tc.prompt)
			a.True(isRedirectStatus(status), "status %d", status)
			returnUrl := visitAccountCreation(t, p, location)

			status, location = browsePromptCreate(t, p, returnUrl)
			a.True(isRedirectStatus(status), "status %d", status)
			a.False(p.LoginWasCalled, "the login page was reached")
			if tc.wantConsent {
				a.Equal("/"+strings.TrimPrefix(wicket.UIConstantsDefaultRoutePathsConsent, "/"), pagePath(p, location), "location %s", location)
				return
			}
			a.NotEqual(accountCreation, location.Path, "the account creation page was reached twice")
			requireCode(t, location)
		})
	}
}

func TestPromptCreateRefused(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		configured      bool
		prompt          string
		wantDescription string
	}{
		"not configured": {
			prompt:          "create",
			wantDescription: "prompt value create is not supported",
		},
		"not configured with consent": {
			prompt:          "consent create",
			wantDescription: "prompt value create is not supported",
		},
		"none with create": {
			configured:      true,
			prompt:          "none create",
			wantDescription: "Invalid prompt",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)
			p := newPromptCreatePipeline(t, tc.configured)

			// invalid_request is dispatched through the error page, which
			// carries the error response to the validated redirect URI.
			status, location := authorizeWithPrompt(t, p, tc.prompt)
			a.True(isRedirectStatus(status), "status %d", status)
			a.Equal(integration_common.ErrorPage, pagePath(p, location), "location %s", location)
			browsePromptCreate(t, p, location.String())
			a.True(p.ErrorWasCalled)
			a.NotNil(p.ErrorMessage)
			a.Equal(wicket.AuthorizeErrorsInvalidRequest.Error(), p.ErrorMessage.Error)
			a.Equal(tc.wantDescription, p.ErrorMessage.ErrorDescription)
			a.Equal(createClientId, p.ErrorMessage.ClientId)
			clientResponse, err := url.Parse(p.ErrorMessage.RedirectUri)
			a.NoError(err)
			a.True(strings.HasPrefix(clientResponse.String(), createRedirectUri), "redirect uri %s", clientResponse)
			a.Equal(wicket.AuthorizeErrorsInvalidRequest.Error(), clientResponse.Query().Get("error"))
			a.Equal(tc.wantDescription, clientResponse.Query().Get("error_description"))
			a.Equal("create-state", clientResponse.Query().Get("state"))
			a.False(p.CustomWasCalled)
		})
	}
}

// TestPromptCreateLeavesOtherPromptsUnchanged checks that prompt lists the
// create prompt does not settle behave as before, whether or not account
// creation is configured.
func TestPromptCreateLeavesOtherPromptsUnchanged(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		prompt    string
		signedIn  bool
		wantLogin bool
	}{
		"unknown value is ignored for anonymous":   {prompt: "create foo", wantLogin: true},
		"unknown value is ignored when signed in":  {prompt: "create foo", signedIn: true},
		"login prompt shows the login page":        {prompt: "login", signedIn: true, wantLogin: true},
		"consent prompt alone needs a signed user": {prompt: "consent", wantLogin: true},
	}
	for name, tc := range cases {
		for _, configured := range []bool{false, true} {
			t.Run(name+map[bool]string{false: " not configured", true: " configured"}[configured], func(t *testing.T) {
				t.Parallel()
				a := require.New(t)
				p := newPromptCreatePipeline(t, configured)
				if tc.signedIn {
					a.NoError(p.Login(createSubject))
				}

				status, location := authorizeWithPrompt(t, p, tc.prompt)
				a.True(isRedirectStatus(status), "status %d", status)
				a.NotEqual(accountCreation, location.Path)
				if tc.wantLogin {
					a.Equal("/"+strings.TrimPrefix(wicket.UIConstantsDefaultRoutePathsLogin, "/"), pagePath(p, location), "location %s", location)
					return
				}
				requireCode(t, location)
			})
		}
	}
}
