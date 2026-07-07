// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	optmock "github.com/gonewx/wicket/config/options/mock"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	services_impl "github.com/gonewx/wicket/services/impl"
	svcmock "github.com/gonewx/wicket/services/mock"
	storagemock "github.com/gonewx/wicket/storage/mock"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
	"github.com/stretchr/testify/require"
)

// test/IdentityServer.UnitTests/Endpoints/Results/AuthorizeResultTests.cs
type authorizeResultTests struct {
	subject               *AuthorizeResult
	response              *responses_models.AuthorizeResponse
	options               *config_options.IdentityServerOptions
	mockUserSession       *svcmock.MockUserSession
	mockErrorMessageStore *storagemock.MockMessageStore[messages.ErrorMessage]
	urls                  *services_impl.ServerUrls
	httpRequest           *http.Request
	writer                *test_common.MockHttpWriter
}

func newAuthorizeResultTests() *authorizeResultTests {
	httpRequest := httptest.NewRequest(http.MethodGet, "https://server", nil)
	// httpContextAccessor := accessor.NewHttpContextAccessor()
	// httpContextAccessor.SetRequest(httpRequest)

	options := optmock.NewTestIdentityServerOptions().Create()
	options.UserInteraction.ErrorUrl = "~/error"
	options.UserInteraction.ErrorIdParameter = "errorId"

	writer := test_common.NewMockHttpWriter()
	userSession := svcmock.NewMockUserSession()
	errorMessageStore := storagemock.NewMockMessageStore[messages.ErrorMessage]()
	urls := services_impl.NewServerUrls(httpRequest)

	response := responses_models.NewAuthorizeResponse()
	subject := newAuthorizeResult(
		response,
		options,
		userSession,
		errorMessageStore,
		urls,
		test_common.NewStubClock(),
	)

	return &authorizeResultTests{
		subject:               subject,
		response:              response,
		options:               options,
		urls:                  urls,
		mockUserSession:       userSession,
		mockErrorMessageStore: errorMessageStore,
		httpRequest:           httpRequest,
		writer:                writer,
	}
}

func TestError_should_redirect_to_error_page_and_passs_info(t *testing.T) {
	a := require.New(t)

	tc := newAuthorizeResultTests()
	tc.response.Error = fmt.Errorf("some_error")

	_ = tc.subject.Execute(tc.writer, tc.httpRequest)

	a.Len(tc.mockErrorMessageStore.Messages, 1)
	a.Equal(http.StatusText(http.StatusFound), tc.writer.Header().Get("code"))

	location := tc.writer.Header().Get("Location")
	a.True(strings.HasPrefix(location, "https://server/error"))

	u, err := url.Parse(location)
	a.NoError(err)
	a.Equal(tc.mockErrorMessageStore.Ids[0], u.Query().Get("errorId"))
}

func TestAuthorizeResponseHandlerPromptNoneErrorsShouldReturnToClient(t *testing.T) {
	a := require.New(t)

	errs := []error{
		gois.AuthorizeErrorsAccountSelectionRequired,
		gois.AuthorizeErrorsLoginRequired,
		gois.AuthorizeErrorsConsentRequired,
		gois.AuthorizeErrorsInteractionRequired,
	}

	for _, err := range errs {
		tc := newAuthorizeResultTests()
		tc.response.Error = err

		tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
		tc.response.Request.ResponseMode = gois.ResponseModesQuery
		tc.response.Request.RedirectUri = "http://client/callback"
		tc.response.Request.PromptModes = []string{gois.PromptModesNone}

		_ = tc.subject.Execute(tc.writer, tc.httpRequest)

		a.Len(tc.mockUserSession.Clients, 0)
		a.Equal(http.StatusText(http.StatusFound), tc.writer.Header().Get("code"))

		location := tc.writer.Header().Get("Location")
		a.True(strings.HasPrefix(location, "http://client/callback"))
	}
}

func TestAuthorizeResponseHandlerPromptNoneErrorsForAnonymousUsersShouldIncludeSessionState(t *testing.T) {
	a := require.New(t)

	errs := []error{
		gois.AuthorizeErrorsAccountSelectionRequired,
		gois.AuthorizeErrorsLoginRequired,
		gois.AuthorizeErrorsConsentRequired,
		gois.AuthorizeErrorsInteractionRequired,
	}

	for _, err := range errs {
		tc := newAuthorizeResultTests()
		tc.response.Error = err

		tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
		tc.response.Request.ResponseMode = gois.ResponseModesQuery
		tc.response.Request.RedirectUri = "http://client/callback"
		tc.response.Request.PromptModes = []string{gois.PromptModesNone}

		tc.response.SessionState = "some_session_state"

		_ = tc.subject.Execute(tc.writer, tc.httpRequest)

		a.Len(tc.mockUserSession.Clients, 0)
		a.Equal(http.StatusText(http.StatusFound), tc.writer.Header().Get("code"))

		location := tc.writer.Header().Get("Location")
		a.Contains(location, "session_state=some_session_state")
	}
}

func TestAuthorizeResponseHandlerAccessDeniedShouldReturnToClient(t *testing.T) {
	a := require.New(t)

	const errorDescription = "some error description"

	tc := newAuthorizeResultTests()
	tc.response.Error = gois.AuthorizeErrorsAccessDenied
	tc.response.ErrorDescription = errorDescription

	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ResponseMode = gois.ResponseModesQuery
	tc.response.Request.RedirectUri = "http://client/callback"

	_ = tc.subject.Execute(tc.writer, tc.httpRequest)

	a.Len(tc.mockUserSession.Clients, 0)
	a.Equal(http.StatusText(http.StatusFound), tc.writer.Header().Get("code"))

	location := tc.writer.Header().Get("Location")
	a.True(strings.HasPrefix(location, "http://client/callback"))

	u, err := url.Parse(location)
	a.NoError(err)

	queryParams := u.Query()
	a.Equal(gois.AuthorizeErrorsAccessDenied.Error(), queryParams.Get("error"))
	a.Equal(errorDescription, queryParams.Get("error_description"))
}

func TestAuthorizeResponseHandlerSuccessShouldAddClientToClientList(t *testing.T) {
	a := require.New(t)

	tc := newAuthorizeResultTests()

	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ClientId = "client"
	tc.response.Request.ResponseMode = gois.ResponseModesQuery
	tc.response.Request.RedirectUri = "http://client/callback"

	_ = tc.subject.Execute(tc.writer, tc.httpRequest)

	a.True(utils.Contains(tc.mockUserSession.Clients, "client"))

}

func TestAuthorizeResponseHandlerQueryModeShouldPassResultsInQuery(t *testing.T) {
	a := require.New(t)

	tc := newAuthorizeResultTests()

	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ClientId = "client"
	tc.response.Request.ResponseMode = gois.ResponseModesQuery
	tc.response.Request.RedirectUri = "http://client/callback"
	tc.response.Request.State = "state"

	_ = tc.subject.Execute(tc.writer, tc.httpRequest)

	a.Equal(http.StatusText(http.StatusFound), tc.writer.Header().Get("code"))
	a.Contains(tc.writer.Header().Get("Cache-Control"), "no-store")
	a.Contains(tc.writer.Header().Get("Cache-Control"), "no-cache")
	a.Contains(tc.writer.Header().Get("Cache-Control"), "max-age=0")

	location := tc.writer.Header().Get("Location")
	a.True(strings.HasPrefix(location, "http://client/callback"))
	a.Contains(location, "?state=state")
}

func TestAuthorizeResponseHandlerFragmentModeShouldPassResultsInFragment(t *testing.T) {
	a := require.New(t)

	tc := newAuthorizeResultTests()

	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ClientId = "client"
	tc.response.Request.ResponseMode = gois.ResponseModesFragment
	tc.response.Request.RedirectUri = "http://client/callback"
	tc.response.Request.State = "state"

	_ = tc.subject.Execute(tc.writer, tc.httpRequest)

	a.Equal(http.StatusText(http.StatusFound), tc.writer.Header().Get("code"))
	a.Contains(tc.writer.Header().Get("Cache-Control"), "no-store")
	a.Contains(tc.writer.Header().Get("Cache-Control"), "no-cache")
	a.Contains(tc.writer.Header().Get("Cache-Control"), "max-age=0")

	location := tc.writer.Header().Get("Location")
	a.True(strings.HasPrefix(location, "http://client/callback"))
	a.Contains(location, "#state=state")
}

func TestAuthorizeResponseHandlerFormPostModeShouldPassResultsInBody(t *testing.T) {
	a := require.New(t)

	tc := newAuthorizeResultTests()

	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ClientId = "client"
	tc.response.Request.ResponseMode = gois.ResponseModesFormPost
	tc.response.Request.RedirectUri = "http://client/callback"
	tc.response.Request.State = "state"

	_ = tc.subject.Execute(tc.writer, tc.httpRequest)

	a.Equal(http.StatusText(http.StatusOK), tc.writer.Header().Get("code"))
	a.True(strings.HasPrefix(tc.writer.Header().Get("Content-Type"), "text/html"))
	a.Contains(tc.writer.Header().Get("Cache-Control"), "no-store")
	a.Contains(tc.writer.Header().Get("Cache-Control"), "no-cache")
	a.Contains(tc.writer.Header().Get("Cache-Control"), "max-age=0")
	a.Contains(tc.writer.Header().Get("Content-Security-Policy"), "default-src 'none';")
	a.Contains(tc.writer.Header().Get("Content-Security-Policy"), "script-src 'sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8='")
	a.Contains(tc.writer.Header().Get("X-Content-Security-Policy"), "default-src 'none';")
	a.Contains(tc.writer.Header().Get("X-Content-Security-Policy"), "script-src 'sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8='")

	html := string(tc.writer.Data)
	a.Contains(html, "<base target='_self'/>")
	a.Contains(html, "<form method='post' action='http://client/callback'>")
	a.Contains(html, "<input type='hidden' name='state' value='state' />")
}

func TestAuthorizeResponseHandlerFormPostModeShouldAddUnsafeInlineForCspLevel1(t *testing.T) {
	a := require.New(t)

	tc := newAuthorizeResultTests()

	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ClientId = "client"
	tc.response.Request.ResponseMode = gois.ResponseModesFormPost
	tc.response.Request.RedirectUri = "http://client/callback"
	tc.response.Request.State = "state"

	tc.options.Csp.Level = gois.CspLevelOne

	_ = tc.subject.Execute(tc.writer, tc.httpRequest)

	a.Contains(tc.writer.Header().Get("Content-Security-Policy"), "script-src 'unsafe-inline' 'sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8='")
	a.Contains(tc.writer.Header().Get("X-Content-Security-Policy"), "script-src 'unsafe-inline' 'sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8='")
}

func TestAuthorizeResponseHandlerFormPostModeShouldNotAddDeprecatedHeaderWhenItIsDisabled(t *testing.T) {
	a := require.New(t)

	tc := newAuthorizeResultTests()

	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ClientId = "client"
	tc.response.Request.ResponseMode = gois.ResponseModesFormPost
	tc.response.Request.RedirectUri = "http://client/callback"
	tc.response.Request.State = "state"

	tc.options.Csp.AddDeprecatedHeader = false

	_ = tc.subject.Execute(tc.writer, tc.httpRequest)

	a.Contains(tc.writer.Header().Get("Content-Security-Policy"), "script-src 'sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8='")
	a.Empty(tc.writer.Header().Get("X-Content-Security-Policy"))
}
