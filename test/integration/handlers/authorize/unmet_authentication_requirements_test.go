// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package authorize

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

const (
	acrClientId    = "acr-client"
	acrRedirectUri = "https://acr-client.example/callback"
	acrSubject     = "acr-subject"
	acrState       = "acr-state"
)

// newRequestedAcrPipeline builds a pipeline with one authorization code
// client; enforced declares that requested acr_values are enforced.
func newRequestedAcrPipeline(t *testing.T, enforced bool) *integration_common.WicketPipeline {
	t.Helper()
	return newRequestedAcrPipelineWith(t, enforced, "")
}

// newRequestedAcrPipelineWith also declares the account creation page when
// creation is not empty.
func newRequestedAcrPipelineWith(t *testing.T, enforced bool, creation string) *integration_common.WicketPipeline {
	t.Helper()
	client := storage_models.NewClient()
	client.ClientId = acrClientId
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.RequireConsent = false
	client.RedirectUris = []string{acrRedirectUri}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId}
	require.NoError(t, client.SetAllowedGrantTypes(wicket.GrantTypesCode))

	p := integration_common.NewWicketPipeline()
	p.Clients = []*storage_models.Client{client}
	p.IdentityScopes = []*storage_models.IdentityResource{storage_models.IdentityResourcesOpenId()}
	user := test.NewTestUser()
	user.SubjectId = acrSubject
	user.Username = acrSubject
	p.Users = []*test.TestUser{user}
	if enforced {
		p.Root.ServerConfig().RequireRequestedAcr()
	}
	if creation != "" {
		p.Root.ServerConfig().SetAccountCreationUrl(creation)
	}
	p.Initialize()
	t.Cleanup(p.TestServer.Close)
	p.BrowserClient.AllowAutoRedirect = false
	return p
}

// acrPrincipal is the subject the host signs in, with the given acr claim;
// an empty acr leaves the claim out.
func acrPrincipal(t *testing.T, acr string) *claims.ClaimsPrincipal {
	t.Helper()
	user := models.NewLocalUser(models.WithLocalUserSubjectId(acrSubject))
	user.IdentityProvider = wicket.LocalIdentityProvider
	if acr != "" {
		user.AdditionalClaims = []*claims.Claim{claims.NewClaim(
			claims.WithClaimType(wicket.JwtClaimTypesAuthenticationContextClassReference),
			claims.WithClaimValue(acr),
		)}
	}
	principal, err := user.CreatePrincipal()
	require.NoError(t, err)
	return principal
}

func authorizeWithAcr(t *testing.T, p *integration_common.WicketPipeline, acrValues string, prompt string) (int, *url.URL) {
	t.Helper()
	extra := url.Values{}
	if prompt != "" {
		extra.Set(wicket.AuthorizeRequestPrompt, prompt)
	}
	u, err := p.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     acrClientId,
		ResponseType: wicket.ResponseTypesCode,
		Scope:        wicket.StandardScopesOpenId,
		RedirectUri:  acrRedirectUri,
		State:        acrState,
		Nonce:        "acr-nonce",
		AcrValues:    acrValues,
		Extra:        extra,
	})
	require.NoError(t, err)
	return browsePromptCreate(t, p, u.String())
}

// acrOutcome is where an authorize response sent the browser.
type acrOutcome struct {
	login       *url.URL
	code        string
	clientError string
	state       string
	iss         string
}

func classifyAcr(t *testing.T, p *integration_common.WicketPipeline, status int, location *url.URL) acrOutcome {
	t.Helper()
	require.True(t, isRedirectStatus(status), "status %d", status)
	if pagePath(p, location) == integration_common.LoginPage {
		return acrOutcome{login: location}
	}
	require.True(t, strings.HasPrefix(location.String(), acrRedirectUri), "location %s", location)
	query := location.Query()
	return acrOutcome{code: query.Get("code"), clientError: query.Get("error"), state: query.Get("state"), iss: query.Get("iss")}
}

// authorizeAcr sends an authorize request and classifies the response.
func authorizeAcr(t *testing.T, p *integration_common.WicketPipeline, acrValues string, prompt string) acrOutcome {
	t.Helper()
	status, location := authorizeWithAcr(t, p, acrValues, prompt)
	return classifyAcr(t, p, status, location)
}

// signInOnLoginPage has the host's login page sign in a subject with acr and
// returns the outcome of the request the page returns to.
func signInOnLoginPage(t *testing.T, p *integration_common.WicketPipeline, login *url.URL, acr string) acrOutcome {
	t.Helper()
	a := require.New(t)
	returnUrl := login.Query().Get(p.Options.UserInteraction.LoginReturnUrlParameter)
	a.NotEmpty(returnUrl)
	p.Subject = acrPrincipal(t, acr)
	status, back := browsePromptCreate(t, p, login.String())
	a.True(isRedirectStatus(status), "login page answered %d", status)
	a.NotNil(p.LoginRequest)
	a.Contains(p.LoginRequest.AcrValues, "urn:a")

	p.LoginWasCalled = false
	status, location := browsePromptCreate(t, p, back.String())
	o := classifyAcr(t, p, status, location)
	a.False(p.LoginWasCalled)
	a.Nil(o.login, "the login page was reached twice")
	return o
}

func requireAcrCode(t *testing.T, o acrOutcome) {
	t.Helper()
	require.NotEmpty(t, o.code, "outcome %+v", o)
	require.Empty(t, o.clientError)
	require.Equal(t, acrState, o.state)
}

func requireUnmet(t *testing.T, p *integration_common.WicketPipeline, o acrOutcome) {
	t.Helper()
	require.Equal(t, wicket.AuthorizeErrorsUnmetAuthenticationRequirements.Error(), o.clientError, "outcome %+v", o)
	require.Empty(t, o.code)
	require.Equal(t, acrState, o.state)
	require.Equal(t, p.TestServer.URL, o.iss, "the client response lacks the issuer")
	require.False(t, p.ErrorWasCalled, "the error page was reached")
}

func requireSuppressedLogin(t *testing.T, p *integration_common.WicketPipeline, login *url.URL) {
	t.Helper()
	returnUrl, err := url.Parse(login.Query().Get(p.Options.UserInteraction.LoginReturnUrlParameter))
	require.NoError(t, err)
	require.Equal(t, wicket.PromptModesLogin, returnUrl.Query().Get(wicket.SuppressedPrompt), "return url %s", returnUrl)
}

func TestRequestedAcrNotEnforcedByDefault(t *testing.T) {
	t.Parallel()
	a := require.New(t)
	p := newRequestedAcrPipeline(t, false)
	a.NoError(p.LoginWithPrincipal(acrPrincipal(t, "")))
	p.LoginWasCalled = false

	o := authorizeAcr(t, p, "urn:a", "")
	requireAcrCode(t, o)
	a.False(p.LoginWasCalled)
}

func TestRequestedAcrSatisfiedBySession(t *testing.T) {
	t.Parallel()
	a := require.New(t)
	p := newRequestedAcrPipeline(t, true)
	a.NoError(p.LoginWithPrincipal(acrPrincipal(t, "urn:a")))
	p.LoginWasCalled = false

	o := authorizeAcr(t, p, "urn:b urn:a", "")
	requireAcrCode(t, o)
	a.False(p.LoginWasCalled)
}

func TestRequestedAcrStepUp(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		session   string // acr of an existing session; "-" for none
		prompt    string
		signInAcr string
		wantCode  bool
	}{
		"session too weak, step up succeeds":      {session: "urn:low", signInAcr: "urn:a", wantCode: true},
		"session too weak, step up fails":         {session: "urn:low", signInAcr: "urn:low"},
		"no session, satisfied after login":       {session: "-", signInAcr: "urn:a", wantCode: true},
		"no session, not satisfied after login":   {session: "-", signInAcr: "urn:low"},
		"prompt=login, satisfied after login":     {session: "urn:a", prompt: "login", signInAcr: "urn:a", wantCode: true},
		"prompt=login, not satisfied after login": {session: "urn:a", prompt: "login", signInAcr: "urn:low"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)
			p := newRequestedAcrPipeline(t, true)
			if tc.session != "-" {
				a.NoError(p.LoginWithPrincipal(acrPrincipal(t, tc.session)))
			}

			first := authorizeAcr(t, p, "urn:a", tc.prompt)
			a.NotNil(first.login, "outcome %+v, want the login page", first)
			requireSuppressedLogin(t, p, first.login)

			o := signInOnLoginPage(t, p, first.login, tc.signInAcr)
			if tc.wantCode {
				requireAcrCode(t, o)
				return
			}
			requireUnmet(t, p, o)
		})
	}
}

func TestRequestedAcrPromptNone(t *testing.T) {
	t.Parallel()
	a := require.New(t)
	p := newRequestedAcrPipeline(t, true)
	a.NoError(p.LoginWithPrincipal(acrPrincipal(t, "urn:low")))
	p.LoginWasCalled = false

	o := authorizeAcr(t, p, "urn:a", wicket.PromptModesNone)
	requireUnmet(t, p, o)
	a.False(p.LoginWasCalled)
}

// TestRequestedAcrHintPrefixesOnly checks that the identity provider and
// tenant hints are not authentication classes: enforced or not, the outcome
// is the same.
func TestRequestedAcrHintPrefixesOnly(t *testing.T) {
	t.Parallel()

	outcomes := map[bool]acrOutcome{}
	for _, enforced := range []bool{false, true} {
		p := newRequestedAcrPipeline(t, enforced)
		require.NoError(t, p.LoginWithPrincipal(acrPrincipal(t, "")))
		o := authorizeAcr(t, p, wicket.KnownAcrValuesHomeRealm+wicket.LocalIdentityProvider+" "+wicket.KnownAcrValuesTenant+"t", "")
		o.code = strings.Repeat("x", len(o.code)) // codes and issuers differ per run
		o.iss = ""
		if o.login != nil {
			o.login = &url.URL{Path: o.login.Path}
		}
		outcomes[enforced] = o
	}
	require.Equal(t, outcomes[false], outcomes[true])
	require.NotEmpty(t, outcomes[true].code)
}

// TestRequestedAcrAfterAccountCreation checks that the step-up after an
// account creation round trip keeps the create prompt suppressed: the login
// page is visited once and the account creation page is not visited again.
func TestRequestedAcrAfterAccountCreation(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		signInAcr string
		wantCode  bool
	}{
		"satisfied after the step up":     {signInAcr: "urn:a", wantCode: true},
		"not satisfied after the step up": {signInAcr: "urn:low"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)
			p := newRequestedAcrPipelineWith(t, true, accountCreation)

			status, location := authorizeWithAcr(t, p, "urn:a", wicket.PromptModesCreate)
			a.True(isRedirectStatus(status), "status %d", status)
			a.Equal(accountCreation, pagePath(p, location), "location %s", location)
			returnUrl := location.Query().Get(p.Options.UserInteraction.CustomRedirectReturnUrlParameter)
			a.NotEmpty(returnUrl)

			// the account creation page signs the new user in with a weaker acr.
			a.NoError(p.LoginWithPrincipal(acrPrincipal(t, "urn:low")))
			p.CustomWasCalled = false
			status, location = browsePromptCreate(t, p, returnUrl)
			first := classifyAcr(t, p, status, location)
			a.NotNil(first.login, "outcome %+v, want the login page", first)
			stepUpReturn, err := url.Parse(first.login.Query().Get(p.Options.UserInteraction.LoginReturnUrlParameter))
			a.NoError(err)
			a.Equal(wicket.PromptModesCreate+" "+wicket.PromptModesLogin, stepUpReturn.Query().Get(wicket.SuppressedPrompt))

			o := signInOnLoginPage(t, p, first.login, tc.signInAcr)
			a.False(p.CustomWasCalled, "the account creation page was reached twice")
			if tc.wantCode {
				requireAcrCode(t, o)
				return
			}
			requireUnmet(t, p, o)
		})
	}
}
