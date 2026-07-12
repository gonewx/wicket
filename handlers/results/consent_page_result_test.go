// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"errors"
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

func TestConsentPageResult_Execute_redirects_to_consent_page(t *testing.T) {
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
			options.UserInteraction.ConsentUrl = "/consent"
			options.UserInteraction.ConsentReturnUrlParameter = "returnUrl"

			request := newInteractionRequest()
			httpRequest := httptest.NewRequest(http.MethodGet, "https://server", nil)
			urls := services_impl.NewServerUrls(httpRequest)

			var store storage.AuthorizationParametersMessageStore
			if tc.useStore {
				store = test_common.NewQueryStringAuthorizationParametersMessageStore()
			} else {
				httpRequest = withEmptyScope(httpRequest)
			}

			result := &ConsentPageResult{
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
			a.Truef(strings.HasPrefix(location, "https://server/consent"), "location=%s", location)
			a.Falsef(strings.HasPrefix(location, request.RedirectUri), "must not redirect to the client callback, location=%s", location)

			returnURLValue := extractReturnURL(a, location, options.UserInteraction.ConsentReturnUrlParameter)
			assertReturnUrlAccepted(a, options, urls, store, returnURLValue)
			assertParameterCarriage(a, returnURLValue, tc.useStore)
		})
	}
}

// TestConsentPageResult_Execute_returns_store_error proves the store failure path
// through redirectUrl propagates out of Execute without emitting a redirect. The
// store branch is shared by all three page results, so covering it once guards
// every Execute's error return.
func TestConsentPageResult_Execute_returns_store_error(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	options := optmock.NewTestWicketOptions().Create()
	options.UserInteraction.ConsentUrl = "/consent"
	options.UserInteraction.ConsentReturnUrlParameter = "returnUrl"

	httpRequest := httptest.NewRequest(http.MethodGet, "https://server", nil)
	urls := services_impl.NewServerUrls(httpRequest)

	wantErr := errors.New("store unavailable")
	result := &ConsentPageResult{
		request:                             newInteractionRequest(),
		options:                             options,
		urls:                                urls,
		authorizationParametersMessageStore: errWriteStore{err: wantErr},
	}

	writer := httptest.NewRecorder()
	err := result.Execute(writer, httpRequest)

	a.ErrorIs(err, wantErr)
	a.Empty(writer.Header().Get("Location"))
	a.Equal(http.StatusOK, writer.Code)
}
