// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	optmock "github.com/gonewx/wicket/config/options/mock"
	services_impl "github.com/gonewx/wicket/services/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
	"github.com/stretchr/testify/require"
)

func TestRedirectStatusCode(t *testing.T) {
	t.Parallel()

	enabled := config_options.NewWicketOptions()
	enabled.UseSeeOtherRedirects = true

	cases := map[string]struct {
		options *config_options.WicketOptions
		want    int
	}{
		"nil options":  {options: nil, want: http.StatusFound},
		"switch off":   {options: config_options.NewWicketOptions(), want: http.StatusFound},
		"switch on":    {options: enabled, want: http.StatusSeeOther},
		"zero options": {options: &config_options.WicketOptions{}, want: http.StatusFound},
		"zero with on": {options: &config_options.WicketOptions{UseSeeOtherRedirects: true}, want: http.StatusSeeOther},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, redirectStatusCode(tc.options))
		})
	}
}

// redirectCase runs one result with the switch set to useSeeOther and
// returns the status code and Location it produced.
type redirectCase func(useSeeOther bool) (int, string)

func authorizeRedirectCase(configure func(tc *authorizeResultTests)) redirectCase {
	return func(useSeeOther bool) (int, string) {
		tc := newAuthorizeResultTests()
		tc.options.UseSeeOtherRedirects = useSeeOther
		configure(tc)
		_ = tc.subject.Execute(tc.writer, tc.httpRequest)
		return tc.writer.Code, stripStoreHandle(tc.writer.Header().Get("Location"))
	}
}

// stripStoreHandle drops the query of an error or logout page location: the
// message id there is a fresh store handle per run, so only the target is
// compared.
func stripStoreHandle(location string) string {
	for _, page := range []string{"https://server/error", "https://server/logout"} {
		if strings.HasPrefix(location, page+"?") {
			return page
		}
	}
	return location
}

func interactionRedirectCase(build func(useSeeOther bool) interface {
	Execute(http.ResponseWriter, *http.Request) error
}) redirectCase {
	return func(useSeeOther bool) (int, string) {
		httpRequest := httptest.NewRequest(http.MethodPost, "https://server", nil)
		writer := httptest.NewRecorder()
		_ = build(useSeeOther).Execute(writer, httpRequest)
		return writer.Code, writer.Header().Get("Location")
	}
}

func TestRedirectResults_use_see_other_when_enabled(t *testing.T) {
	t.Parallel()

	interactionOptions := func(useSeeOther bool) *config_options.WicketOptions {
		options := optmock.NewTestWicketOptions().Create()
		options.UserInteraction.LoginUrl = "/account/login"
		options.UserInteraction.LoginReturnUrlParameter = "returnUrl"
		options.UserInteraction.ConsentUrl = "/consent"
		options.UserInteraction.ConsentReturnUrlParameter = "returnUrl"
		options.UserInteraction.CustomRedirectReturnUrlParameter = "returnUrl"
		options.UseSeeOtherRedirects = useSeeOther
		return options
	}
	urls := services_impl.NewServerUrls(httptest.NewRequest(http.MethodGet, "https://server", nil))

	cases := map[string]redirectCase{
		"authorize query mode": authorizeRedirectCase(func(tc *authorizeResultTests) {
			tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
			tc.response.Request.ClientId = "client"
			tc.response.Request.ResponseMode = wicket.ResponseModesQuery
			tc.response.Request.RedirectUri = "http://client/callback"
			tc.response.Request.State = "state"
		}),
		"authorize fragment mode": authorizeRedirectCase(func(tc *authorizeResultTests) {
			tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
			tc.response.Request.ClientId = "client"
			tc.response.Request.ResponseMode = wicket.ResponseModesFragment
			tc.response.Request.RedirectUri = "http://client/callback"
			tc.response.Request.State = "state"
		}),
		"authorize error page": authorizeRedirectCase(func(tc *authorizeResultTests) {
			tc.response.Error = fmt.Errorf("some_error")
		}),
		"login page": interactionRedirectCase(func(useSeeOther bool) interface {
			Execute(http.ResponseWriter, *http.Request) error
		} {
			return &LoginPageResult{
				request:                             newInteractionRequest(),
				options:                             interactionOptions(useSeeOther),
				urls:                                urls,
				authorizationParametersMessageStore: test_common.NewQueryStringAuthorizationParametersMessageStore(),
			}
		}),
		"consent page": interactionRedirectCase(func(useSeeOther bool) interface {
			Execute(http.ResponseWriter, *http.Request) error
		} {
			return &ConsentPageResult{
				request:                             newInteractionRequest(),
				options:                             interactionOptions(useSeeOther),
				urls:                                urls,
				authorizationParametersMessageStore: test_common.NewQueryStringAuthorizationParametersMessageStore(),
			}
		}),
		"custom redirect": interactionRedirectCase(func(useSeeOther bool) interface {
			Execute(http.ResponseWriter, *http.Request) error
		} {
			return &CustomRedirectResult{
				request:                             newInteractionRequest(),
				redirectTarget:                      "https://custom/interaction",
				options:                             interactionOptions(useSeeOther),
				urls:                                urls,
				authorizationParametersMessageStore: test_common.NewQueryStringAuthorizationParametersMessageStore(),
			}
		}),
		"end session": func(useSeeOther bool) (int, string) {
			test := newEndSessionResultTests()
			test.options.UseSeeOtherRedirects = useSeeOther
			validatedRequest := validators_models.NewValidatedEndSessionRequest()
			validatedRequest.Client = storage_models.NewClient()
			validatedRequest.Client.ClientId = "client"
			test.result.ValidatedRequest = validatedRequest
			_ = test.subject.Execute(test.writer, test.httpRequest)
			return test.writer.Code, stripStoreHandle(test.writer.Header().Get("Location"))
		},
	}

	for name, run := range cases {
		run := run
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)

			offCode, offLocation := run(false)
			onCode, onLocation := run(true)

			a.Equal(http.StatusFound, offCode)
			a.Equal(http.StatusSeeOther, onCode)
			a.NotEmpty(onLocation)
			a.Equal(offLocation, onLocation, "the switch must change only the status code")
		})
	}
}

func TestAuthorizeResult_form_post_ignores_see_other_switch(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	tc := newAuthorizeResultTests()
	tc.options.UseSeeOtherRedirects = true
	tc.response.Request = validators_models.NewValidatedAuthorizeRequest()
	tc.response.Request.ClientId = "client"
	tc.response.Request.ResponseMode = wicket.ResponseModesFormPost
	tc.response.Request.RedirectUri = "http://client/callback"
	tc.response.Request.State = "state"

	err := tc.subject.Execute(tc.writer, tc.httpRequest)

	a.NoError(err)
	a.Equal(http.StatusOK, tc.writer.Code)
	a.Empty(tc.writer.Header().Get("Location"))
	a.Contains(tc.writer.Body.String(), "<form")
}
