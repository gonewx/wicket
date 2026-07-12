// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	optmock "github.com/gonewx/wicket/config/options/mock"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/stretchr/testify/require"
)

func TestLoginPageResult_Execute_redirects_to_login_page(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		useStore bool
	}{
		"inlines authorize parameters when no store is wired": {useStore: false},
		"references a stored handle when a store is wired":    {useStore: true},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)

			options := optmock.NewTestWicketOptions().Create()
			options.UserInteraction.LoginUrl = "/account/login"
			options.UserInteraction.LoginReturnUrlParameter = "returnUrl"

			request := newInteractionRequest()
			httpRequest := httptest.NewRequest(http.MethodGet, "https://server", nil)
			urls := services_impl.NewServerUrls(httpRequest)

			var store storage.AuthorizationParametersMessageStore
			if tc.useStore {
				store = test_common.NewQueryStringAuthorizationParametersMessageStore()
			} else {
				httpRequest = withEmptyScope(httpRequest)
			}

			result := &LoginPageResult{
				request:                             request,
				options:                             options,
				urls:                                urls,
				authorizationParametersMessageStore: store,
			}

			writer := httptest.NewRecorder()
			err := result.Execute(writer, httpRequest)

			a.NoError(err)
			a.Equal(http.StatusFound, writer.Code)

			location := writer.Header().Get("Location")
			a.Truef(strings.HasPrefix(location, "https://server/account/login"), "location=%s", location)
			a.Falsef(strings.HasPrefix(location, request.RedirectUri), "must not redirect to the client callback, location=%s", location)

			returnURLValue := extractReturnURL(a, location, options.UserInteraction.LoginReturnUrlParameter)
			assertReturnUrlAccepted(a, options, urls, store, returnURLValue)
			assertParameterCarriage(a, returnURLValue, tc.useStore)
		})
	}
}
