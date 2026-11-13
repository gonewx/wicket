// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	switchTestSecret      = "secret"
	switchTestFormType    = "application/x-www-form-urlencoded"
	switchTestJsonType    = "application/json"
	switchTestCredentials = "client_id=switch.client&client_secret=" + switchTestSecret
	switchTestWrongSecret = "client_id=switch.client&client_secret=wrong"
)

// switchCallCounter is shared by every double of one handler under test, so a
// single number tells whether the handler reached any of its dependencies.
type switchCallCounter struct {
	calls int
}

// switchClientValidator authenticates a request by the secret in its parsed
// form body and counts every call.
type switchClientValidator struct {
	counter *switchCallCounter
}

func (v *switchClientValidator) Validate(r *http.Request) *validators_models.ClientSecretValidationResult {
	v.counter.calls++
	result := validators_models.NewClientSecretValidationResult()
	if r.PostForm.Get("client_secret") != switchTestSecret {
		result.Error = wicket.TokenErrorsInvalidClient
		return result
	}
	client := storage_models.NewClient()
	client.ClientId = "switch.client"
	result.Client = client
	return result
}

// switchApiValidator authenticates an API by the secret in the parsed form
// body and counts every call.
type switchApiValidator struct {
	counter *switchCallCounter
}

func (v *switchApiValidator) Validate(r *http.Request) *validators_models.ApiSecretValidationResult {
	v.counter.calls++
	result := validators_models.NewApiSecretValidationResult()
	if r.PostForm.Get("client_secret") != switchTestSecret {
		result.Error = wicket.TokenErrorsInvalidClient
	}
	return result
}

type switchTokenRequestValidator struct {
	counter *switchCallCounter
}

func (v *switchTokenRequestValidator) ValidateRequest(context.Context, url.Values, *validators_models.ClientSecretValidationResult) (*validators_models.TokenRequestValidationResult, error) {
	v.counter.calls++
	return validators_models.NewTokenRequestValidationResult(validators_models.NewValidatedTokenRequest()), nil
}

type switchTokenResponseGenerator struct {
	counter *switchCallCounter
}

func (g *switchTokenResponseGenerator) Handle(context.Context, *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	g.counter.calls++
	return &responses_models.TokenResponse{AccessToken: "opaque-access-token", AccessTokenLifetime: 3600}, nil
}

type switchIntrospectionRequestValidator struct {
	counter *switchCallCounter
}

func (v *switchIntrospectionRequestValidator) Validate(context.Context, url.Values, *storage_models.ApiResource) (*validators_models.IntrospectionRequestValidationResult, error) {
	v.counter.calls++
	return validators_models.NewIntrospectionRequestValidationResult(), nil
}

type switchIntrospectionResponseGenerator struct {
	counter *switchCallCounter
}

func (g *switchIntrospectionResponseGenerator) Handle(context.Context, *validators_models.IntrospectionRequestValidationResult) map[string]any {
	g.counter.calls++
	return map[string]any{"active": true}
}

type switchBackchannelRequestValidator struct {
	counter *switchCallCounter
}

func (v *switchBackchannelRequestValidator) Validate(context.Context, url.Values, *storage_models.Client) *validators_models.BackchannelAuthenticationRequestValidationResult {
	v.counter.calls++
	result := validators_models.NewBackchannelAuthenticationRequestValidationResult()
	result.Request = &storage_models.BackchannelAuthenticationRequest{RequestId: "opaque-request-id"}
	result.ExpiresIn = 300
	return result
}

type switchAuthorizeRequestValidator struct {
	counter *switchCallCounter
}

func (v *switchAuthorizeRequestValidator) Validate(context.Context, url.Values, *claims.ClaimsPrincipal) *validators_models.AuthorizeRequestValidationResult {
	v.counter.calls++
	return validators_models.NewAuthorizeRequestValidationResult(validRequest())
}

type switchInteractionGenerator struct {
	counter *switchCallCounter
}

func (g *switchInteractionGenerator) Handle(context.Context, *validators_models.ValidatedAuthorizeRequest, *messages.ConsentResponse) *responses_models.InteractionResponse {
	g.counter.calls++
	return responses_models.NewInteractionResponse()
}

func (g *switchInteractionGenerator) HandleLogin(context.Context, *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
	g.counter.calls++
	return nil
}

func (g *switchInteractionGenerator) HandleConsent(context.Context, *validators_models.ValidatedAuthorizeRequest, *messages.ConsentResponse) *responses_models.InteractionResponse {
	g.counter.calls++
	return nil
}

type switchAuthorizeResponseGenerator struct {
	counter *switchCallCounter
}

func (g *switchAuthorizeResponseGenerator) Create(context.Context, *validators_models.ValidatedAuthorizeRequest) (*responses_models.AuthorizeResponse, error) {
	g.counter.calls++
	return responses_models.NewAuthorizeResponse(), nil
}

// switchUserSession counts every session call, GetUser included.
type switchUserSession struct {
	counter *switchCallCounter
}

func (s *switchUserSession) EnsureSessionIdCookie(context.Context) error {
	s.counter.calls++
	return nil
}

func (s *switchUserSession) RemoveSessionIdCookie() error {
	s.counter.calls++
	return nil
}

func (s *switchUserSession) CreateSessionId(context.Context, *claims.ClaimsPrincipal, *auth.Properties) (string, error) {
	s.counter.calls++
	return "", nil
}

func (s *switchUserSession) GetSessionId() string {
	s.counter.calls++
	return ""
}

func (s *switchUserSession) GetClientList() ([]string, error) {
	s.counter.calls++
	return nil, nil
}

func (s *switchUserSession) GetUser() *claims.ClaimsPrincipal {
	s.counter.calls++
	return nil
}

func (s *switchUserSession) AddClientId(context.Context, string) error {
	s.counter.calls++
	return nil
}

func (s *switchUserSession) Item(string) (any, bool) {
	s.counter.calls++
	return nil, false
}

func (s *switchUserSession) SetItem(string, any) {
	s.counter.calls++
}

// switchConsentStore is an in-memory consent store that counts Read, Write and
// Delete. Seeding goes straight to the map and is not counted.
type switchConsentStore struct {
	counter *switchCallCounter
	entries map[string]*messages.Message[*messages.ConsentResponse]
}

func (s *switchConsentStore) Write(_ context.Context, id string, message *messages.Message[*messages.ConsentResponse]) error {
	s.counter.calls++
	s.entries[id] = message
	return nil
}

func (s *switchConsentStore) Read(_ context.Context, id string) (*messages.Message[*messages.ConsentResponse], error) {
	s.counter.calls++
	return s.entries[id], nil
}

func (s *switchConsentStore) Delete(_ context.Context, id string) error {
	s.counter.calls++
	delete(s.entries, id)
	return nil
}

// switchParametersStore holds one stored set of authorize parameters under a
// fixed handle and counts every call.
type switchParametersStore struct {
	counter *switchCallCounter
	stored  url.Values
}

const switchParametersHandle = "stored-handle"

func (s *switchParametersStore) Write(context.Context, *messages.Message[url.Values]) (string, error) {
	s.counter.calls++
	return switchParametersHandle, nil
}

func (s *switchParametersStore) Read(_ context.Context, handle string) (*messages.Message[url.Values], error) {
	s.counter.calls++
	if handle != switchParametersHandle {
		return nil, nil
	}
	return messages.NewMessage(s.stored), nil
}

func (s *switchParametersStore) Delete(context.Context, string) error {
	s.counter.calls++
	return nil
}

// switchRequest describes one request sent to a handler under test.
type switchRequest struct {
	name        string
	method      string
	target      string
	contentType string
	body        string
	// openStatus is the exact status the handler answers while its switch is
	// on. Zero marks a request that is only sent while the switch is off: with
	// the switch on, the authorize handlers hand such a request to a result
	// that needs a request scope, which a directly built handler does not have.
	openStatus int
	// reachesDependencies tells whether the handler calls any dependency for
	// this request while its switch is on.
	reachesDependencies bool
}

func (c switchRequest) build() *http.Request {
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	request := httptest.NewRequest(c.method, c.target, body)
	if c.contentType != "" {
		request.Header.Set("Content-Type", c.contentType)
	}
	return request
}

// switchSubject is one handler built over fresh counting doubles.
type switchSubject struct {
	process func(w http.ResponseWriter, r *http.Request) error
	counter *switchCallCounter
	// untouched reports a problem when state the handler must leave alone
	// while switched off has changed; nil when there is no such state.
	untouched func() string
}

// switchFixture describes one handler and the switch that governs it.
type switchFixture struct {
	name   string
	toggle func(endpoints *config_options.EndpointsOptions, on bool)
	build  func(options *config_options.WicketOptions) *switchSubject
	// requests are sent with the switch off; those with an openStatus are also
	// sent with the switch on.
	requests []switchRequest
	// probe is the request used where one request stands for the handler: the
	// repeated-read, nil-options and foreign-switch tests.
	probe switchRequest
}

// switchToggles names the four switches this file is about, so each fixture
// can be exercised against the three it must ignore.
var switchToggles = map[string]func(endpoints *config_options.EndpointsOptions, on bool){
	"EnableAuthorizeEndpoint": func(endpoints *config_options.EndpointsOptions, on bool) {
		endpoints.EnableAuthorizeEndpoint = on
	},
	"EnableTokenEndpoint": func(endpoints *config_options.EndpointsOptions, on bool) {
		endpoints.EnableTokenEndpoint = on
	},
	"EnableIntrospectionEndpoint": func(endpoints *config_options.EndpointsOptions, on bool) {
		endpoints.EnableIntrospectionEndpoint = on
	},
	"EnableBackchannelAuthenticationEndpoint": func(endpoints *config_options.EndpointsOptions, on bool) {
		endpoints.EnableBackchannelAuthenticationEndpoint = on
	},
}

func switchCallbackValues() url.Values {
	return url.Values{
		wicket.AuthorizeRequestClientId: {"some-client"},
		wicket.AuthorizeRequestScope:    {"openid"},
		wicket.AuthorizeRequestNonce:    {"some-nonce"},
	}
}

func switchFixtures() []switchFixture {
	const (
		tokenUrl      = "https://wicket.test/connect/token"
		introspectUrl = "https://wicket.test/connect/introspect"
		cibaUrl       = "https://wicket.test/connect/ciba"
		authorizeUrl  = "https://wicket.test/connect/authorize"
		callbackUrl   = "https://wicket.test/connect/authorize/callback"
	)
	authorizeQuery := url.Values{
		wicket.AuthorizeRequestClientId:     {"some-client"},
		wicket.AuthorizeRequestResponseType: {"code"},
		wicket.AuthorizeRequestScope:        {"openid"},
		wicket.AuthorizeRequestRedirectUri:  {"https://client.example/callback"},
	}.Encode()

	tokenValid := switchRequest{
		name: "valid request", method: http.MethodPost, target: tokenUrl, contentType: switchTestFormType,
		body:       "grant_type=client_credentials&" + switchTestCredentials,
		openStatus: http.StatusOK, reachesDependencies: true,
	}
	introspectionValid := switchRequest{
		name: "valid request", method: http.MethodPost, target: introspectUrl, contentType: switchTestFormType,
		body:       "token=opaque&" + switchTestCredentials,
		openStatus: http.StatusOK, reachesDependencies: true,
	}
	cibaValid := switchRequest{
		name: "valid request", method: http.MethodPost, target: cibaUrl, contentType: switchTestFormType,
		body:       "scope=openid&login_hint=bob&" + switchTestCredentials,
		openStatus: http.StatusOK, reachesDependencies: true,
	}
	authorizeJson := switchRequest{
		name: "POST JSON", method: http.MethodPost, target: authorizeUrl, contentType: switchTestJsonType,
		body:       `{"client_id":"some-client"}`,
		openStatus: http.StatusUnsupportedMediaType,
	}
	callbackPost := switchRequest{
		name: "POST with a body", method: http.MethodPost, target: callbackUrl + "?" + switchCallbackValues().Encode(),
		contentType: switchTestFormType, body: "client_id=some-client",
		openStatus: http.StatusMethodNotAllowed,
	}

	return []switchFixture{
		{
			name:   "token",
			toggle: switchToggles["EnableTokenEndpoint"],
			build: func(options *config_options.WicketOptions) *switchSubject {
				counter := &switchCallCounter{}
				handler := NewTokenHandlerWithOptions(
					&switchClientValidator{counter: counter},
					&switchTokenRequestValidator{counter: counter},
					&switchTokenResponseGenerator{counter: counter},
					options,
					quietLogger(),
				)
				return &switchSubject{process: handler.Process, counter: counter}
			},
			// The token handler has no method check today, so GET reaches the
			// client validator and PUT is served. The switched-on statuses for
			// those two record that behavior as the control; they are not a
			// promise that the endpoint accepts these methods.
			requests: []switchRequest{
				tokenValid,
				{name: "GET", method: http.MethodGet, target: tokenUrl, openStatus: http.StatusBadRequest, reachesDependencies: true},
				{name: "PUT", method: http.MethodPut, target: tokenUrl, contentType: switchTestFormType, body: "grant_type=client_credentials&" + switchTestCredentials, openStatus: http.StatusOK, reachesDependencies: true},
				{name: "POST JSON", method: http.MethodPost, target: tokenUrl, contentType: switchTestJsonType, body: `{"grant_type":"client_credentials"}`, openStatus: http.StatusBadRequest, reachesDependencies: true},
				{name: "unparseable form body", method: http.MethodPost, target: tokenUrl, contentType: switchTestFormType, body: "grant_type=%zz", openStatus: http.StatusBadRequest},
				{name: "wrong credentials", method: http.MethodPost, target: tokenUrl, contentType: switchTestFormType, body: "grant_type=client_credentials&" + switchTestWrongSecret, openStatus: http.StatusBadRequest, reachesDependencies: true},
			},
			probe: tokenValid,
		},
		{
			name:   "introspection",
			toggle: switchToggles["EnableIntrospectionEndpoint"],
			build: func(options *config_options.WicketOptions) *switchSubject {
				counter := &switchCallCounter{}
				handler := NewIntrospectionHandlerWithOptions(
					&switchApiValidator{counter: counter},
					&switchIntrospectionRequestValidator{counter: counter},
					&switchIntrospectionResponseGenerator{counter: counter},
					options,
					quietLogger(),
				)
				return &switchSubject{process: handler.Process, counter: counter}
			},
			requests: []switchRequest{
				introspectionValid,
				{name: "GET", method: http.MethodGet, target: introspectUrl, openStatus: http.StatusMethodNotAllowed},
				{name: "PUT", method: http.MethodPut, target: introspectUrl, contentType: switchTestFormType, body: "token=opaque&" + switchTestCredentials, openStatus: http.StatusMethodNotAllowed},
				{name: "POST JSON", method: http.MethodPost, target: introspectUrl, contentType: switchTestJsonType, body: `{"token":"opaque"}`, openStatus: http.StatusUnsupportedMediaType},
				{name: "unparseable form body", method: http.MethodPost, target: introspectUrl, contentType: switchTestFormType, body: "token=%zz", openStatus: http.StatusBadRequest},
				{name: "wrong credentials", method: http.MethodPost, target: introspectUrl, contentType: switchTestFormType, body: "token=opaque&" + switchTestWrongSecret, openStatus: http.StatusUnauthorized, reachesDependencies: true},
			},
			probe: introspectionValid,
		},
		{
			name:   "backchannel authentication",
			toggle: switchToggles["EnableBackchannelAuthenticationEndpoint"],
			build: func(options *config_options.WicketOptions) *switchSubject {
				counter := &switchCallCounter{}
				handler := NewBackchannelAuthenticationHandlerWithOptions(
					&switchClientValidator{counter: counter},
					&switchBackchannelRequestValidator{counter: counter},
					options,
				)
				return &switchSubject{process: handler.Process, counter: counter}
			},
			// As with the token handler, there is no method check today; the
			// switched-on GET and PUT statuses record that, not a promise.
			requests: []switchRequest{
				cibaValid,
				{name: "GET", method: http.MethodGet, target: cibaUrl, openStatus: http.StatusBadRequest, reachesDependencies: true},
				{name: "PUT", method: http.MethodPut, target: cibaUrl, contentType: switchTestFormType, body: "scope=openid&login_hint=bob&" + switchTestCredentials, openStatus: http.StatusOK, reachesDependencies: true},
				{name: "POST JSON", method: http.MethodPost, target: cibaUrl, contentType: switchTestJsonType, body: `{"scope":"openid"}`, openStatus: http.StatusBadRequest, reachesDependencies: true},
				{name: "unparseable form body", method: http.MethodPost, target: cibaUrl, contentType: switchTestFormType, body: "scope=%zz", openStatus: http.StatusBadRequest},
				{name: "wrong credentials", method: http.MethodPost, target: cibaUrl, contentType: switchTestFormType, body: "scope=openid&login_hint=bob&" + switchTestWrongSecret, openStatus: http.StatusBadRequest, reachesDependencies: true},
			},
			probe: cibaValid,
		},
		{
			name:   "authorize",
			toggle: switchToggles["EnableAuthorizeEndpoint"],
			build: func(options *config_options.WicketOptions) *switchSubject {
				counter := &switchCallCounter{}
				handler := NewAuthorizeHandlerWithOptions(
					&switchAuthorizeRequestValidator{counter: counter},
					&switchInteractionGenerator{counter: counter},
					&switchAuthorizeResponseGenerator{counter: counter},
					&switchUserSession{counter: counter},
					options,
					quietLogger(),
				)
				return &switchSubject{process: handler.Process, counter: counter}
			},
			requests: []switchRequest{
				{name: "valid GET", method: http.MethodGet, target: authorizeUrl + "?" + authorizeQuery},
				{name: "valid POST form", method: http.MethodPost, target: authorizeUrl, contentType: switchTestFormType, body: authorizeQuery},
				authorizeJson,
				{name: "PUT without a form", method: http.MethodPut, target: authorizeUrl, contentType: switchTestJsonType, body: `{"client_id":"some-client"}`, openStatus: http.StatusUnsupportedMediaType},
				{name: "unparseable form body", method: http.MethodPost, target: authorizeUrl, contentType: switchTestFormType, body: "client_id=%zz", openStatus: http.StatusUnsupportedMediaType},
			},
			probe: authorizeJson,
		},
		{
			name:   "authorize callback",
			toggle: switchToggles["EnableAuthorizeEndpoint"],
			build: func(options *config_options.WicketOptions) *switchSubject {
				counter := &switchCallCounter{}
				values := switchCallbackValues()
				// The session double has no subject, so the consent answer a
				// served callback would consume sits under the subjectless key
				// of the inline parameters and of the stored ones alike.
				seeded := grantedConsentMessage()
				consent := &switchConsentStore{
					counter: counter,
					entries: map[string]*messages.Message[*messages.ConsentResponse]{consentRequestKey(nil, values): seeded},
				}
				handler := NewAuthorizeCallbackHandlerWithOptions(
					&switchAuthorizeRequestValidator{counter: counter},
					&switchInteractionGenerator{counter: counter},
					&switchAuthorizeResponseGenerator{counter: counter},
					&switchUserSession{counter: counter},
					consent,
					&switchParametersStore{counter: counter, stored: values},
					options,
					quietLogger(),
				)
				return &switchSubject{
					process: handler.Process,
					counter: counter,
					untouched: func() string {
						if len(consent.entries) != 1 || consent.entries[consentRequestKey(nil, values)] != seeded {
							return "the stored consent answer was changed or removed"
						}
						return ""
					},
				}
			},
			requests: []switchRequest{
				{name: "valid GET with inline parameters", method: http.MethodGet, target: callbackUrl + "?" + switchCallbackValues().Encode()},
				{name: "valid GET with a stored parameters handle", method: http.MethodGet, target: callbackUrl + "?" + url.Values{wicket.AuthorizationParamsStoreMessageStoreIdParameterName: {switchParametersHandle}}.Encode()},
				callbackPost,
				{name: "PUT", method: http.MethodPut, target: callbackUrl + "?" + switchCallbackValues().Encode(), openStatus: http.StatusMethodNotAllowed},
			},
			probe: callbackPost,
		},
	}
}

func switchOptions(toggle func(endpoints *config_options.EndpointsOptions, on bool), on bool) *config_options.WicketOptions {
	options := config_options.NewWicketOptions()
	toggle(options.Endpoints, on)
	return options
}

// requireSwitchedOffAnswer asserts the whole shape of a switched-off answer:
// 404, nothing written, no dependency reached and the request left unread.
func requireSwitchedOffAnswer(t *testing.T, subject *switchSubject, sent switchRequest) {
	t.Helper()

	request := sent.build()
	recorder := httptest.NewRecorder()
	if err := subject.process(recorder, request); err != nil {
		t.Fatalf("Process error = %v, want nil", err)
	}
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", recorder.Body.String())
	}
	// The handler must set no header at all; checking the whole map also
	// covers Content-Type, WWW-Authenticate, Location, Set-Cookie and
	// Cache-Control under any spelling of their names.
	if len(recorder.Header()) != 0 {
		t.Fatalf("handler set headers %v, want none", recorder.Header())
	}
	if written := recorder.Result().Header; len(written) != 0 {
		t.Fatalf("response carries headers %v, want none", written)
	}
	if subject.counter.calls != 0 {
		t.Fatalf("dependency calls = %d, want 0", subject.counter.calls)
	}
	if request.Form != nil || request.PostForm != nil {
		t.Fatal("a switched-off endpoint parsed the request form")
	}
	remaining, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if string(remaining) != sent.body {
		t.Fatalf("request body left = %q, want the whole body %q", remaining, sent.body)
	}
	if subject.untouched != nil {
		if problem := subject.untouched(); problem != "" {
			t.Fatal(problem)
		}
	}
}

// requireSwitchedOnAnswer asserts the exact status a request gets while the
// switch does not stop it, and that dependencies are reached where the request
// gets that far.
func requireSwitchedOnAnswer(t *testing.T, subject *switchSubject, sent switchRequest) {
	t.Helper()

	recorder := httptest.NewRecorder()
	if err := subject.process(recorder, sent.build()); err != nil {
		t.Fatalf("Process error = %v, want nil", err)
	}
	if recorder.Code != sent.openStatus {
		t.Fatalf("status = %d, want %d", recorder.Code, sent.openStatus)
	}
	if sent.reachesDependencies && subject.counter.calls == 0 {
		t.Fatal("dependency calls = 0, want the request to reach its dependencies")
	}
}

func TestEndpointSwitchOffAnswersNotFoundWithoutTouchingTheRequest(t *testing.T) {
	t.Parallel()

	for _, fixture := range switchFixtures() {
		for _, sent := range fixture.requests {
			t.Run(fixture.name+"/"+sent.name, func(t *testing.T) {
				t.Parallel()
				subject := fixture.build(switchOptions(fixture.toggle, false))
				requireSwitchedOffAnswer(t, subject, sent)
			})
		}
	}
}

func TestEndpointSwitchOnServesTheSameRequests(t *testing.T) {
	t.Parallel()

	for _, fixture := range switchFixtures() {
		for _, sent := range fixture.requests {
			if sent.openStatus == 0 {
				continue
			}
			t.Run(fixture.name+"/"+sent.name, func(t *testing.T) {
				t.Parallel()
				subject := fixture.build(switchOptions(fixture.toggle, true))
				requireSwitchedOnAnswer(t, subject, sent)
			})
		}
	}
}

func TestEndpointSwitchIsReadOnEveryRequest(t *testing.T) {
	t.Parallel()

	for _, fixture := range switchFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			options := switchOptions(fixture.toggle, false)
			subject := fixture.build(options)

			requireSwitchedOffAnswer(t, subject, fixture.probe)

			fixture.toggle(options.Endpoints, true)
			requireSwitchedOnAnswer(t, subject, fixture.probe)

			fixture.toggle(options.Endpoints, false)
			before := subject.counter.calls
			recorder := httptest.NewRecorder()
			if err := subject.process(recorder, fixture.probe.build()); err != nil {
				t.Fatalf("Process error = %v, want nil", err)
			}
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status after switching off again = %d, want 404", recorder.Code)
			}
			if subject.counter.calls != before {
				t.Fatalf("dependency calls grew from %d to %d after switching off again", before, subject.counter.calls)
			}
		})
	}
}

func TestEndpointSwitchNilOptionsLeaveTheEndpointOn(t *testing.T) {
	t.Parallel()

	for _, fixture := range switchFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			subject := fixture.build(nil)
			requireSwitchedOnAnswer(t, subject, fixture.probe)
		})
	}
}

func TestEndpointSwitchHandlerObeysOnlyItsOwnSwitch(t *testing.T) {
	t.Parallel()

	for _, fixture := range switchFixtures() {
		for name, toggle := range switchToggles {
			t.Run(fixture.name+"/only "+name+" off", func(t *testing.T) {
				t.Parallel()
				options := switchOptions(toggle, false)

				// Whether this is the fixture's own switch is decided by what
				// the fixture's toggle does to the same options, not by name.
				own := switchOptions(fixture.toggle, false)
				isOwn := *options.Endpoints == *own.Endpoints

				subject := fixture.build(options)
				if isOwn {
					requireSwitchedOffAnswer(t, subject, fixture.probe)
					return
				}
				requireSwitchedOnAnswer(t, subject, fixture.probe)
			})
		}
	}
}
