// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	validators_models "github.com/gonewx/wicket/validators/models"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeClientErrorResultDeliversToTheClient(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{wicket.ResponseModesQuery, wicket.ResponseModesFragment, wicket.ResponseModesFormPost} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)
			tc := newAuthorizeResultTests()
			tc.options.EmitIssuerIdentificationResponseParameter = true
			tc.response.Error = wicket.AuthorizeErrorsUnmetAuthenticationRequirements
			tc.response.ErrorDescription = "requested acr_values could not be satisfied"
			tc.response.Issuer = "https://server"
			tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
			tc.response.Request.ResponseMode = mode
			tc.response.Request.RedirectUri = "https://client/callback"
			tc.response.Request.State = "s1"
			tc.response.Request.ClientId = "client"

			subject := &AuthorizeClientErrorResult{AuthorizeResult: tc.subject}
			a.NoError(subject.Execute(tc.writer, tc.httpRequest))
			a.Empty(tc.mockErrorMessageStore.Messages, "the error page was used")
			a.Empty(tc.mockUserSession.Clients)

			var values url.Values
			switch mode {
			case wicket.ResponseModesFormPost:
				a.Equal(http.StatusOK, tc.writer.Code)
				body := tc.writer.Body.String()
				a.Contains(body, "action='https://client/callback'")
				for _, want := range []string{
					"name='error' value='unmet_authentication_requirements'",
					"name='state' value='s1'",
					"name='iss' value='https://server'",
				} {
					a.Contains(body, want)
				}
				return
			case wicket.ResponseModesQuery:
				a.Equal(http.StatusFound, tc.writer.Code)
				location, err := url.Parse(tc.writer.Header().Get("Location"))
				a.NoError(err)
				a.True(strings.HasPrefix(location.String(), "https://client/callback?"), "location %s", location)
				values = location.Query()
			default:
				a.Equal(http.StatusFound, tc.writer.Code)
				location, err := url.Parse(tc.writer.Header().Get("Location"))
				a.NoError(err)
				a.True(strings.HasPrefix(location.String(), "https://client/callback#"), "location %s", location)
				values, err = url.ParseQuery(location.Fragment)
				a.NoError(err)
			}
			a.Equal("unmet_authentication_requirements", values.Get("error"))
			a.Equal("requested acr_values could not be satisfied", values.Get("error_description"))
			a.Equal("s1", values.Get("state"))
			a.Equal("https://server", values.Get("iss"))
		})
	}
}

// TestAuthorizeResultSendsUnmetAuthenticationRequirementsToTheErrorPage pins
// why the wrapper exists: the plain result treats the error as unsafe.
func TestAuthorizeResultSendsUnmetAuthenticationRequirementsToTheErrorPage(t *testing.T) {
	t.Parallel()
	a := require.New(t)
	tc := newAuthorizeResultTests()
	tc.response.Error = wicket.AuthorizeErrorsUnmetAuthenticationRequirements
	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ResponseMode = wicket.ResponseModesQuery
	tc.response.Request.RedirectUri = "https://client/callback"

	a.NoError(tc.subject.Execute(tc.writer, tc.httpRequest))
	a.Len(tc.mockErrorMessageStore.Messages, 1)
}
