// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
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

// errWriteStore is an AuthorizationParametersMessageStore whose Write always
// fails, so the store error path through redirectUrl and each result's Execute
// can be exercised and its propagation asserted.
type errWriteStore struct{ err error }

func (s errWriteStore) Write(*messages.Message[url.Values]) (string, error) { return "", s.err }
func (errWriteStore) Read(string) (*messages.Message[url.Values], error)    { return nil, nil }
func (errWriteStore) Delete(string) error                                   { return nil }

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

// extractReturnURL pulls the raw return URL carried under paramName in an
// interaction page location, asserting it is present.
func extractReturnURL(a *require.Assertions, location string, paramName string) string {
	parsed, err := url.Parse(location)
	a.NoError(err)

	value := parsed.Query().Get(paramName)
	a.NotEmptyf(value, "expected a %s parameter on %s", paramName, location)

	return value
}

// assertReturnUrlAccepted feeds the emitted return URL back through the real
// OidcReturnUrlParser. This is the property that actually matters: a return URL
// the parser rejects silently drops the original authorize request at the
// callback, so asserting only the location prefix is not enough.
func assertReturnUrlAccepted(
	a *require.Assertions,
	options *config_options.WicketOptions,
	urls services.ServerUrls,
	store storage.AuthorizationParametersMessageStore,
	returnURLValue string,
) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	parser := services_impl.NewOidcReturnUrlParser(options, nil, nil, urls, logger, store)
	a.Truef(parser.IsValidReturnUrl(returnURLValue),
		"return url must be accepted by OidcReturnUrlParser (a local callback URL), got %q", returnURLValue)
}

// assertParameterCarriage checks the return URL query shape: a store-backed
// return URL carries only the opaque handle parameter, an inline one carries the
// original authorize parameters.
func assertParameterCarriage(a *require.Assertions, returnURLValue string, useStore bool) {
	parsed, err := url.Parse(returnURLValue)
	a.NoError(err)
	returnURL := parsed.Query()

	if useStore {
		a.NotEmpty(returnURL.Get(gois.AuthorizationParamsStoreMessageStoreIdParameterName))
		a.Empty(returnURL.Get("client_id"))
	} else {
		a.Equal("client2", returnURL.Get("client_id"))
		a.Equal("code", returnURL.Get("response_type"))
		a.Empty(returnURL.Get(gois.AuthorizationParamsStoreMessageStoreIdParameterName))
	}
}
