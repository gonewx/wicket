// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	optmock "github.com/gonewx/wicket/config/options/mock"
	"github.com/gonewx/wicket/hosting"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	test_common "github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
	"github.com/stretchr/testify/require"
)

// emptyScope is a Provider that resolves nothing. Injecting it lets a result's
// optional parameters store stay nil through Execute's init instead of panicking
// on an absent resolution scope, so the inline branch can be exercised directly.
type emptyScope struct{}

func (emptyScope) GetService(reflect.Type) any              { return nil }
func (emptyScope) IsService(reflect.Type) bool              { return false }
func (emptyScope) IsKeyedService(reflect.Type, any) bool    { return false }
func (emptyScope) GetKeyedService(reflect.Type, any) any    { return nil }
func (emptyScope) GetKeyedServices(reflect.Type, any) []any { return nil }
func (emptyScope) CreateScope() godi.Scope                  { return nil }
func (emptyScope) Close() error                             { return nil }

// authorizeRawValues is a representative set of front-channel authorize
// parameters used to prove they survive the round trip into the return URL.
func authorizeRawValues() url.Values {
	return url.Values{
		"client_id":     {"client2"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"xyz-state"},
		"nonce":         {"n-once"},
	}
}

// newInteractionRequest builds a validated authorize request whose stub redirect
// target is an external client callback, so a correct interaction redirect must
// point somewhere other than this URL.
func newInteractionRequest() *validators_models.ValidatedAuthorizeRequest {
	request := validators_models.NewValidatedAuthorizeRequest()
	request.RedirectUri = "https://client2/callback"
	request.Raw = authorizeRawValues()
	return request
}

// withEmptyScope attaches a resolution scope that resolves nothing, so a nil
// optional store survives Execute's init.
func withEmptyScope(r *http.Request) *http.Request {
	return r.WithContext(hosting.ContextWithScope(r.Context(), emptyScope{}))
}

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

			returnURL := parseReturnURL(a, location, options.UserInteraction.ConsentReturnUrlParameter)
			assertParameterCarriage(a, returnURL, tc.useStore)
		})
	}
}

// parseReturnURL extracts and re-parses the return URL carried under paramName
// in the interaction page location.
func parseReturnURL(a *require.Assertions, location string, paramName string) url.Values {
	parsed, err := url.Parse(location)
	a.NoError(err)

	returnURLValue := parsed.Query().Get(paramName)
	a.NotEmptyf(returnURLValue, "expected a %s parameter on %s", paramName, location)

	returnURL, err := url.Parse(returnURLValue)
	a.NoError(err)

	return returnURL.Query()
}

// assertParameterCarriage checks the return URL query shape: a store-backed
// return URL carries only the opaque handle parameter, an inline one carries the
// original authorize parameters.
func assertParameterCarriage(a *require.Assertions, returnURL url.Values, useStore bool) {
	if useStore {
		a.NotEmpty(returnURL.Get(gois.AuthorizationParamsStoreMessageStoreIdParameterName))
		a.Empty(returnURL.Get("client_id"))
	} else {
		a.Equal("client2", returnURL.Get("client_id"))
		a.Equal("code", returnURL.Get("response_type"))
		a.Empty(returnURL.Get(gois.AuthorizationParamsStoreMessageStoreIdParameterName))
	}
}
