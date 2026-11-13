// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	core_models "github.com/gonewx/wicket/models"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/tokens"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type fakeRevocationRequestValidator struct {
	result     *validators_models.TokenRevocationRequestValidationResult
	err        error
	called     bool
	parameters url.Values
	client     *storage_models.Client
}

func (v *fakeRevocationRequestValidator) ValidateRequest(ctx context.Context, parameters url.Values, client *storage_models.Client) (*validators_models.TokenRevocationRequestValidationResult, error) {
	v.called = true
	v.parameters = parameters
	v.client = client
	return v.result, v.err
}

type fakeRevocationResponseGenerator struct {
	response *responses_models.TokenRevocationResponse
	err      error
	called   bool
}

func (g *fakeRevocationResponseGenerator) Handle(ctx context.Context, result *validators_models.TokenRevocationRequestValidationResult) (*responses_models.TokenRevocationResponse, error) {
	g.called = true
	return g.response, g.err
}

func revocationClient() *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = "revoking.client"
	return client
}

func authenticatedRevocationClient() *validators_models.ClientSecretValidationResult {
	result := validators_models.NewClientSecretValidationResult()
	result.Client = revocationClient()
	return result
}

func failedClientResult(err error) *validators_models.ClientSecretValidationResult {
	result := validators_models.NewClientSecretValidationResult()
	result.Error = err
	result.Description = "internal detail"
	return result
}

func validRevocationResult(hint string) *validators_models.TokenRevocationRequestValidationResult {
	result := validators_models.NewTokenRevocationRequestValidationResult()
	result.Token = "opaque"
	result.TokenTypeHint = hint
	result.Client = revocationClient()
	return result
}

func revocationRequest(method string, target string, body string) *http.Request {
	req := httptest.NewRequest(method, "https://wicket.test/"+wicket.ProtocolRoutePathsRevocation+target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

type revocationOutcome struct {
	recorder  *httptest.ResponseRecorder
	err       error
	validator *fakeRevocationRequestValidator
	generator *fakeRevocationResponseGenerator
}

func runRevocation(
	req *http.Request,
	clientResult *validators_models.ClientSecretValidationResult,
	validator *fakeRevocationRequestValidator,
	generator *fakeRevocationResponseGenerator,
) revocationOutcome {
	if validator == nil {
		validator = &fakeRevocationRequestValidator{result: validRevocationResult("")}
	}
	if generator == nil {
		generator = &fakeRevocationResponseGenerator{response: &responses_models.TokenRevocationResponse{Success: true}}
	}
	handler := NewTokenRevocationHandler(
		&fakeClientSecretValidator{result: clientResult},
		validator,
		generator,
		config_options.NewWicketOptions(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	recorder := httptest.NewRecorder()
	err := handler.Process(recorder, req)
	return revocationOutcome{recorder: recorder, err: err, validator: validator, generator: generator}
}

// recordingRevocationClientValidator is a client authentication double that
// notes whether it was asked.
type recordingRevocationClientValidator struct {
	result *validators_models.ClientSecretValidationResult
	called bool
}

func (v *recordingRevocationClientValidator) Validate(*http.Request) *validators_models.ClientSecretValidationResult {
	v.called = true
	return v.result
}

type revocationSetup struct {
	switchedOff  bool
	clientResult *validators_models.ClientSecretValidationResult
	validator    *fakeRevocationRequestValidator
	generator    *fakeRevocationResponseGenerator
}

type revocationRun struct {
	revocationOutcome
	clientValidator *recordingRevocationClientValidator
	logs            string
}

// runRevocationWith runs one request against a handler whose endpoint switch,
// client authentication and Debug log the test can observe.
func runRevocationWith(req *http.Request, setup revocationSetup) revocationRun {
	if setup.validator == nil {
		setup.validator = &fakeRevocationRequestValidator{result: validRevocationResult("")}
	}
	if setup.generator == nil {
		setup.generator = &fakeRevocationResponseGenerator{response: &responses_models.TokenRevocationResponse{Success: true}}
	}
	clientValidator := &recordingRevocationClientValidator{result: setup.clientResult}
	options := config_options.NewWicketOptions()
	options.Endpoints.EnableTokenRevocationEndpoint = !setup.switchedOff

	var logs bytes.Buffer
	handler := NewTokenRevocationHandler(
		clientValidator,
		setup.validator,
		setup.generator,
		options,
		slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	)
	recorder := httptest.NewRecorder()
	err := handler.Process(recorder, req)
	return revocationRun{
		revocationOutcome: revocationOutcome{recorder: recorder, err: err, validator: setup.validator, generator: setup.generator},
		clientValidator:   clientValidator,
		logs:              logs.String(),
	}
}

// jwtShapedToken has the compact JWT form; its segments decode to
// {"alg":"RS256"}, {"sub":"bob"} and "signature-segment".
const jwtShapedToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJib2IifQ.c2lnbmF0dXJlLXNlZ21lbnQ"

func jwtShapedRevocationResult(hint string) *validators_models.TokenRevocationRequestValidationResult {
	result := validRevocationResult(hint)
	result.Token = jwtShapedToken
	return result
}

func decodeRevocationError(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", recorder.Body.String(), err)
	}
	return body
}

func TestTokenRevocationHandlerRejectsMethodAndContentType(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		request    func() *http.Request
		wantStatus int
	}{
		"GET is not allowed": {
			request:    func() *http.Request { return revocationRequest(http.MethodGet, "", "") },
			wantStatus: http.StatusMethodNotAllowed,
		},
		"PUT is not allowed": {
			request:    func() *http.Request { return revocationRequest(http.MethodPut, "", "token=a") },
			wantStatus: http.StatusMethodNotAllowed,
		},
		"JSON body is unsupported": {
			request: func() *http.Request {
				req := revocationRequest(http.MethodPost, "", `{"token":"a"}`)
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			wantStatus: http.StatusUnsupportedMediaType,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := runRevocation(tt.request(), authenticatedRevocationClient(), nil, nil)
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			if out.recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", out.recorder.Code, tt.wantStatus)
			}
			if out.validator.called || out.generator.called {
				t.Fatal("request reached validation or revocation")
			}
		})
	}
}

func TestTokenRevocationHandlerMalformedFormIsInvalidRequest(t *testing.T) {
	t.Parallel()

	out := runRevocation(revocationRequest(http.MethodPost, "", "token=%zz"), authenticatedRevocationClient(), nil, nil)
	if out.err != nil {
		t.Fatalf("Process error = %v", out.err)
	}
	if out.recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", out.recorder.Code)
	}
	if got := decodeRevocationError(t, out.recorder)["error"]; got != wicket.TokenErrorsInvalidRequest.Error() {
		t.Fatalf("error = %v, want invalid_request", got)
	}
}

func TestTokenRevocationHandlerClientAuthenticationFailure(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		authorization  *string
		clientResult   *validators_models.ClientSecretValidationResult
		wantStatus     int
		wantChallenge  string
		wantNoProtocol bool
	}{
		"wrong secret in Basic header is 401 with a Basic challenge": {
			authorization: stringRef("Basic " + "Y2xpZW50Ondyb25n"),
			clientResult:  failedClientResult(wicket.TokenErrorsInvalidClient),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Basic realm="wicket"`,
		},
		"lower case basic scheme gets the Basic challenge": {
			authorization: stringRef("basic Y2xpZW50Ondyb25n"),
			clientResult:  failedClientResult(wicket.TokenErrorsInvalidClient),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Basic realm="wicket"`,
		},
		"other scheme is echoed without parameters": {
			authorization: stringRef("Bearer abc.def"),
			clientResult:  failedClientResult(wicket.TokenErrorsInvalidRequest),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: "Bearer",
		},
		"empty Authorization header gets the Basic challenge": {
			authorization: stringRef(""),
			clientResult:  failedClientResult(wicket.TokenErrorsInvalidRequest),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Basic realm="wicket"`,
		},
		"unreadable scheme gets the Basic challenge": {
			authorization: stringRef("Ba(sic abc"),
			clientResult:  failedClientResult(wicket.TokenErrorsInvalidClient),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Basic realm="wicket"`,
		},
		"wrong secret in body is 400": {
			clientResult: failedClientResult(wicket.TokenErrorsInvalidClient),
			wantStatus:   http.StatusBadRequest,
		},
		"no credentials is 400 invalid_client": {
			clientResult: failedClientResult(wicket.TokenErrorsInvalidRequest),
			wantStatus:   http.StatusBadRequest,
		},
		"nil client result is 400 invalid_client": {
			clientResult: nil,
			wantStatus:   http.StatusBadRequest,
		},
		"result without client is 400 invalid_client": {
			clientResult: validators_models.NewClientSecretValidationResult(),
			wantStatus:   http.StatusBadRequest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := revocationRequest(http.MethodPost, "", "token=opaque")
			if tt.authorization != nil {
				req.Header["Authorization"] = []string{*tt.authorization}
			}
			out := runRevocation(req, tt.clientResult, nil, nil)
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			if out.recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", out.recorder.Code, tt.wantStatus)
			}
			if got := out.recorder.Header().Get("WWW-Authenticate"); got != tt.wantChallenge {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, tt.wantChallenge)
			}
			if got := out.recorder.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", got)
			}
			body := decodeRevocationError(t, out.recorder)
			if body["error"] != wicket.TokenErrorsInvalidClient.Error() {
				t.Fatalf("error = %v, want invalid_client", body["error"])
			}
			if _, ok := body["error_description"]; ok {
				t.Fatalf("error_description must not be returned: %v", body)
			}
			if out.validator.called || out.generator.called {
				t.Fatal("failed client authentication reached validation or revocation")
			}
		})
	}
}

func TestTokenRevocationHandlerEmptyBodyIsInvalidRequest(t *testing.T) {
	t.Parallel()

	req := revocationRequest(http.MethodPost, "", "")
	req.SetBasicAuth("revoking.client", "secret")
	out := runRevocation(req, authenticatedRevocationClient(), nil, nil)
	if out.err != nil {
		t.Fatalf("Process error = %v", out.err)
	}
	if out.recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", out.recorder.Code)
	}
	if got := decodeRevocationError(t, out.recorder)["error"]; got != wicket.TokenErrorsInvalidRequest.Error() {
		t.Fatalf("error = %v, want invalid_request", got)
	}
	if out.validator.called {
		t.Fatal("empty body reached the request validator")
	}
}

func TestTokenRevocationHandlerValidationErrors(t *testing.T) {
	t.Parallel()

	for name, protocolErr := range map[string]error{
		"missing token":          wicket.TokenErrorsInvalidRequest,
		"unsupported token type": wicket.RevocationErrorsUnsupportedTokenType,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validators_models.NewTokenRevocationRequestValidationResult()
			result.Error = protocolErr
			out := runRevocation(
				revocationRequest(http.MethodPost, "", "token_type_hint=id_token"),
				authenticatedRevocationClient(),
				&fakeRevocationRequestValidator{result: result},
				nil,
			)
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			if out.recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", out.recorder.Code)
			}
			if got := decodeRevocationError(t, out.recorder)["error"]; got != protocolErr.Error() {
				t.Fatalf("error = %v, want %v", got, protocolErr)
			}
			if out.generator.called {
				t.Fatal("rejected request reached revocation")
			}
		})
	}
}

func TestTokenRevocationHandlerInfrastructureErrorsSurface(t *testing.T) {
	t.Parallel()

	failure := errors.New("store unavailable")

	t.Run("validator error", func(t *testing.T) {
		t.Parallel()
		out := runRevocation(
			revocationRequest(http.MethodPost, "", "token=opaque"),
			authenticatedRevocationClient(),
			&fakeRevocationRequestValidator{err: failure},
			nil,
		)
		if !errors.Is(out.err, failure) {
			t.Fatalf("Process error = %v, want wrapping %v", out.err, failure)
		}
		if out.generator.called {
			t.Fatal("validator failure reached revocation")
		}
	})

	t.Run("generator error", func(t *testing.T) {
		t.Parallel()
		out := runRevocation(
			revocationRequest(http.MethodPost, "", "token=opaque"),
			authenticatedRevocationClient(),
			nil,
			&fakeRevocationResponseGenerator{err: failure},
		)
		if !errors.Is(out.err, failure) {
			t.Fatalf("Process error = %v, want wrapping %v", out.err, failure)
		}
		if out.recorder.Header().Get("Pragma") != "" || out.recorder.Body.Len() != 0 {
			t.Fatal("generator failure wrote a response")
		}
	})
}

func TestTokenRevocationHandlerAnswersOkWhetherOrNotFound(t *testing.T) {
	t.Parallel()

	for name, response := range map[string]*responses_models.TokenRevocationResponse{
		"token found":                {Success: true, TokenType: wicket.TokenTypeHintsRefreshToken},
		"token not found":            {Success: false, TokenType: wicket.TokenTypeHintsRefreshToken},
		"not found with stray error": {Success: false, Error: wicket.TokenErrorsInvalidRequest},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := runRevocation(
				revocationRequest(http.MethodPost, "", "token=opaque"),
				authenticatedRevocationClient(),
				nil,
				&fakeRevocationResponseGenerator{response: response},
			)
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			if out.recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", out.recorder.Code)
			}
			if out.recorder.Body.Len() != 0 {
				t.Fatalf("body = %q, want empty", out.recorder.Body.String())
			}
			cacheControl := strings.Join(out.recorder.Header().Values("Cache-Control"), ",")
			if !strings.Contains(cacheControl, "no-store") || !strings.Contains(cacheControl, "no-cache") {
				t.Fatalf("Cache-Control = %q, want no-store and no-cache", cacheControl)
			}
			if got := out.recorder.Header().Get("Pragma"); got != "no-cache" {
				t.Fatalf("Pragma = %q, want no-cache", got)
			}
		})
	}
}

func TestTokenRevocationHandlerReadsOnlyBodyParameters(t *testing.T) {
	t.Parallel()

	t.Run("query token is ignored", func(t *testing.T) {
		t.Parallel()
		out := runRevocation(
			revocationRequest(http.MethodPost, "?token=from-query&token_type_hint=refresh_token", "token=from-body"),
			authenticatedRevocationClient(),
			nil,
			nil,
		)
		if out.err != nil {
			t.Fatalf("Process error = %v", out.err)
		}
		if got := out.validator.parameters["token"]; len(got) != 1 || got[0] != "from-body" {
			t.Fatalf("token parameters = %v, want only the body value", got)
		}
		if _, ok := out.validator.parameters["token_type_hint"]; ok {
			t.Fatal("query token_type_hint reached the validator")
		}
		if out.validator.client == nil || out.validator.client.ClientId != "revoking.client" {
			t.Fatalf("validator client = %v, want the authenticated client", out.validator.client)
		}
	})

	t.Run("query only token leaves the body without a token", func(t *testing.T) {
		t.Parallel()
		out := runRevocation(
			revocationRequest(http.MethodPost, "?token=from-query", "client_id=revoking.client"),
			authenticatedRevocationClient(),
			nil,
			nil,
		)
		if out.err != nil {
			t.Fatalf("Process error = %v", out.err)
		}
		if _, ok := out.validator.parameters["token"]; ok {
			t.Fatal("query token reached the validator")
		}
	})

	t.Run("query only parameters with an empty body are invalid_request", func(t *testing.T) {
		t.Parallel()
		out := runRevocation(
			revocationRequest(http.MethodPost, "?token=from-query", ""),
			authenticatedRevocationClient(),
			nil,
			nil,
		)
		if out.err != nil {
			t.Fatalf("Process error = %v", out.err)
		}
		if out.recorder.Code != http.StatusBadRequest || out.validator.called {
			t.Fatalf("status = %d, validator called = %v; want 400 without validation", out.recorder.Code, out.validator.called)
		}
	})
}

func stringRef(s string) *string { return &s }

func TestTokenRevocationHandlerSwitchedOffIsNotFound(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		request      func() *http.Request
		clientResult *validators_models.ClientSecretValidationResult
	}{
		"POST with valid credentials": {
			request:      func() *http.Request { return revocationRequest(http.MethodPost, "", "token=opaque") },
			clientResult: authenticatedRevocationClient(),
		},
		"GET": {
			request:      func() *http.Request { return revocationRequest(http.MethodGet, "", "") },
			clientResult: authenticatedRevocationClient(),
		},
		"PUT": {
			request:      func() *http.Request { return revocationRequest(http.MethodPut, "", "token=opaque") },
			clientResult: authenticatedRevocationClient(),
		},
		"DELETE": {
			request:      func() *http.Request { return revocationRequest(http.MethodDelete, "", "") },
			clientResult: authenticatedRevocationClient(),
		},
		"JSON body": {
			request: func() *http.Request {
				req := revocationRequest(http.MethodPost, "", `{"token":"opaque"}`)
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			clientResult: authenticatedRevocationClient(),
		},
		"malformed form": {
			request:      func() *http.Request { return revocationRequest(http.MethodPost, "", "token=%zz") },
			clientResult: authenticatedRevocationClient(),
		},
		"wrong secret in Basic header": {
			request: func() *http.Request {
				req := revocationRequest(http.MethodPost, "", "token=opaque")
				req.SetBasicAuth("revoking.client", "wrong")
				return req
			},
			clientResult: failedClientResult(wicket.TokenErrorsInvalidClient),
		},
		"wrong secret in body": {
			request: func() *http.Request {
				return revocationRequest(http.MethodPost, "", "client_id=revoking.client&client_secret=wrong&token=opaque")
			},
			clientResult: failedClientResult(wicket.TokenErrorsInvalidClient),
		},
		"JWT shaped token": {
			request: func() *http.Request {
				return revocationRequest(http.MethodPost, "", "token="+jwtShapedToken)
			},
			clientResult: authenticatedRevocationClient(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := tt.request()
			out := runRevocationWith(req, revocationSetup{switchedOff: true, clientResult: tt.clientResult})
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			response := out.recorder.Result()
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", response.StatusCode)
			}
			if out.recorder.Body.Len() != 0 {
				t.Fatalf("body = %q, want empty", out.recorder.Body.String())
			}
			if got := response.Header.Values("WWW-Authenticate"); len(got) != 0 {
				t.Fatalf("WWW-Authenticate = %q, want none", got)
			}
			if out.clientValidator.called {
				t.Fatal("a switched-off endpoint authenticated the client")
			}
			if out.validator.called || out.generator.called {
				t.Fatal("a switched-off endpoint reached validation or revocation")
			}
			if req.Form != nil || req.PostForm != nil {
				t.Fatal("a switched-off endpoint parsed the request form")
			}
		})
	}
}

func TestTokenRevocationHandlerRejectsJwtShapedToken(t *testing.T) {
	t.Parallel()

	for name, hint := range map[string]string{
		"without hint":            "",
		"with access_token hint":  wicket.TokenTypeHintsAccessToken,
		"with refresh_token hint": wicket.TokenTypeHintsRefreshToken,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := url.Values{"token": {jwtShapedToken}}
			if hint != "" {
				body.Set("token_type_hint", hint)
			}
			out := runRevocationWith(
				revocationRequest(http.MethodPost, "", body.Encode()),
				revocationSetup{
					clientResult: authenticatedRevocationClient(),
					validator:    &fakeRevocationRequestValidator{result: jwtShapedRevocationResult(hint)},
				},
			)
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			if out.recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", out.recorder.Code)
			}
			answer := decodeRevocationError(t, out.recorder)
			if answer["error"] != wicket.RevocationErrorsUnsupportedTokenType.Error() {
				t.Fatalf("error = %v, want unsupported_token_type", answer["error"])
			}
			if len(answer) != 1 {
				t.Fatalf("body = %v, want only the error key", answer)
			}
			if !out.clientValidator.called || !out.validator.called {
				t.Fatal("the request was rejected before client authentication and request validation")
			}
			if out.generator.called {
				t.Fatal("a JWT shaped token reached revocation")
			}
		})
	}
}

// A JWT shaped token and an unsupported hint are answered with the same error
// code, and a client must not be able to tell the two apart.
func TestTokenRevocationHandlerJwtRejectionMatchesUnsupportedHintAnswer(t *testing.T) {
	t.Parallel()

	request := func() *http.Request {
		return revocationRequest(http.MethodPost, "", "token="+jwtShapedToken+"&token_type_hint=id_token")
	}

	rejectedByValidator := validators_models.NewTokenRevocationRequestValidationResult()
	rejectedByValidator.Error = wicket.RevocationErrorsUnsupportedTokenType
	byHint := runRevocationWith(request(), revocationSetup{
		clientResult: authenticatedRevocationClient(),
		validator:    &fakeRevocationRequestValidator{result: rejectedByValidator},
	})
	byForm := runRevocationWith(request(), revocationSetup{
		clientResult: authenticatedRevocationClient(),
		validator:    &fakeRevocationRequestValidator{result: jwtShapedRevocationResult("")},
	})
	if byHint.err != nil || byForm.err != nil {
		t.Fatalf("Process errors = %v, %v", byHint.err, byForm.err)
	}
	if byHint.generator.called || byForm.generator.called {
		t.Fatal("a rejected request reached revocation")
	}

	// Result holds the headers as they stood when the status was written,
	// which is what a client receives.
	hintResponse, formResponse := byHint.recorder.Result(), byForm.recorder.Result()
	if hintResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("status for the unsupported hint = %d, want 400", hintResponse.StatusCode)
	}
	if formResponse.StatusCode != hintResponse.StatusCode {
		t.Fatalf("status = %d, want %d as for the unsupported hint", formResponse.StatusCode, hintResponse.StatusCode)
	}
	if got, want := byForm.recorder.Body.String(), byHint.recorder.Body.String(); got != want {
		t.Fatalf("body = %q, want %q as for the unsupported hint", got, want)
	}
	if !reflect.DeepEqual(formResponse.Header, hintResponse.Header) {
		t.Fatalf("headers = %v, want %v as for the unsupported hint", formResponse.Header, hintResponse.Header)
	}
}

func TestTokenRevocationHandlerClientAuthenticationPrecedesJwtRejection(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		withHeader bool
		wantStatus int
	}{
		"credentials in the Authorization header": {withHeader: true, wantStatus: http.StatusUnauthorized},
		"no Authorization header":                 {withHeader: false, wantStatus: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := revocationRequest(http.MethodPost, "", "token="+jwtShapedToken)
			if tt.withHeader {
				req.SetBasicAuth("revoking.client", "wrong")
			}
			out := runRevocationWith(req, revocationSetup{
				clientResult: failedClientResult(wicket.TokenErrorsInvalidClient),
				validator:    &fakeRevocationRequestValidator{result: jwtShapedRevocationResult("")},
			})
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			if out.recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", out.recorder.Code, tt.wantStatus)
			}
			if got := decodeRevocationError(t, out.recorder)["error"]; got != wicket.TokenErrorsInvalidClient.Error() {
				t.Fatalf("error = %v, want invalid_client", got)
			}
			if out.validator.called || out.generator.called {
				t.Fatal("failed client authentication reached validation or revocation")
			}
		})
	}
}

func TestTokenRevocationHandlerValidatorErrorPrecedesJwtRejection(t *testing.T) {
	t.Parallel()

	for name, protocolErr := range map[string]error{
		"invalid_request":        wicket.TokenErrorsInvalidRequest,
		"unsupported_token_type": wicket.RevocationErrorsUnsupportedTokenType,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := jwtShapedRevocationResult("")
			result.Error = protocolErr
			out := runRevocationWith(
				revocationRequest(http.MethodPost, "", "token="+jwtShapedToken),
				revocationSetup{
					clientResult: authenticatedRevocationClient(),
					validator:    &fakeRevocationRequestValidator{result: result},
				},
			)
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			if out.recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", out.recorder.Code)
			}
			if got := decodeRevocationError(t, out.recorder)["error"]; got != protocolErr.Error() {
				t.Fatalf("error = %v, want %v", got, protocolErr)
			}
			if out.generator.called {
				t.Fatal("rejected request reached revocation")
			}
		})
	}
}

func TestTokenRevocationHandlerJwtRejectionLogDoesNotCarryTheToken(t *testing.T) {
	t.Parallel()

	out := runRevocationWith(
		revocationRequest(http.MethodPost, "", "token="+jwtShapedToken+"&token_type_hint=access_token"),
		revocationSetup{
			clientResult: authenticatedRevocationClient(),
			validator:    &fakeRevocationRequestValidator{result: jwtShapedRevocationResult(wicket.TokenTypeHintsAccessToken)},
		},
	)
	if out.err != nil {
		t.Fatalf("Process error = %v", out.err)
	}
	if out.recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", out.recorder.Code)
	}

	for _, want := range []string{"revoking.client", wicket.TokenTypeHintsAccessToken, wicket.RevocationErrorsUnsupportedTokenType.Error()} {
		if !strings.Contains(out.logs, want) {
			t.Fatalf("log = %q, want it to name %q", out.logs, want)
		}
	}
	forbidden := append([]string{jwtShapedToken}, strings.Split(jwtShapedToken, ".")...)
	// The decoded header, claims and signature segment.
	forbidden = append(forbidden, "RS256", "bob", "signature-segment")
	for _, fragment := range forbidden {
		if strings.Contains(out.logs, fragment) {
			t.Fatalf("log carries token material %q: %s", fragment, out.logs)
		}
	}
}

// With the request validator the endpoint is assembled with behind the
// handler, nothing a revocation request logs at debug level carries the token,
// the client secret posted with it or the client's stored secret.
func TestTokenRevocationHandlerRequestLogCarriesNoCredentials(t *testing.T) {
	t.Parallel()

	const (
		handle       = "5f0c2a9e7b1d4c38a6e0f4927d3b8c15"
		postedSecret = "posted-client-secret"
		storedSecret = "c3RvcmVkLWhhc2hlZC1jbGllbnQtc2VjcmV0"
	)

	formats := map[string]func(io.Writer, *slog.HandlerOptions) slog.Handler{
		"json": func(w io.Writer, opts *slog.HandlerOptions) slog.Handler { return slog.NewJSONHandler(w, opts) },
		"text": func(w io.Writer, opts *slog.HandlerOptions) slog.Handler { return slog.NewTextHandler(w, opts) },
	}
	cases := []struct {
		name       string
		token      string
		hint       string
		wantStatus int
	}{
		{name: "handle without hint", token: handle, wantStatus: http.StatusOK},
		{name: "handle with access token hint", token: handle, hint: wicket.TokenTypeHintsAccessToken, wantStatus: http.StatusOK},
		{name: "handle with refresh token hint", token: handle, hint: wicket.TokenTypeHintsRefreshToken, wantStatus: http.StatusOK},
		{name: "handle with unsupported hint", token: handle, hint: "bogus", wantStatus: http.StatusBadRequest},
		{name: "JWT form", token: jwtShapedToken, hint: wicket.TokenTypeHintsAccessToken, wantStatus: http.StatusBadRequest},
	}

	for formatName, newHandler := range formats {
		for _, tc := range cases {
			t.Run(formatName+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				var logs bytes.Buffer
				logger := slog.New(newHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

				secret := storage_models.NewSecret()
				secret.Value = storedSecret
				clientResult := authenticatedRevocationClient()
				clientResult.Client.ClientSecrets = []*storage_models.Secret{secret}

				handler := NewTokenRevocationHandler(
					&fakeClientSecretValidator{result: clientResult},
					validators_impl.NewTokenRevocationRequestValidator(logger),
					&fakeRevocationResponseGenerator{response: &responses_models.TokenRevocationResponse{Success: true}},
					config_options.NewWicketOptions(),
					logger,
				)

				form := url.Values{}
				form.Set("token", tc.token)
				form.Set("client_id", clientResult.Client.ClientId)
				form.Set("client_secret", postedSecret)
				if tc.hint != "" {
					form.Set("token_type_hint", tc.hint)
				}

				recorder := httptest.NewRecorder()
				if err := handler.Process(recorder, revocationRequest(http.MethodPost, "", form.Encode())); err != nil {
					t.Fatalf("Process error = %v", err)
				}
				if recorder.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d", recorder.Code, tc.wantStatus)
				}

				// The validator's own record shows the request went through it.
				for _, want := range []string{"ValidateRequestAsync result", clientResult.Client.ClientId} {
					if !strings.Contains(logs.String(), want) {
						t.Fatalf("log = %q, want it to hold %q", logs.String(), want)
					}
				}
				forbidden := []string{tc.token, postedSecret, storedSecret, "ClientSecrets"}
				if segments := strings.Split(tc.token, "."); len(segments) > 1 {
					forbidden = append(forbidden, segments...)
				}
				for _, fragment := range forbidden {
					if strings.Contains(logs.String(), fragment) {
						t.Errorf("log carries %q: %s", fragment, logs.String())
					}
				}
			})
		}
	}
}

var errValidationKeysUnavailable = errors.New("validation keys unavailable")

// recordingValidationKeys counts how often access token validation asks for
// the validation keys, which it does for a JWT only, and stops it there.
type recordingValidationKeys struct {
	calls int
}

func (k *recordingValidationKeys) GetSigningCredentials(context.Context, []string) (*tokens.SigningCredentials, error) {
	return nil, errors.New("unexpected call")
}

func (k *recordingValidationKeys) GetAllSigningCredentials(context.Context) ([]*tokens.SigningCredentials, error) {
	return nil, errors.New("unexpected call")
}

func (k *recordingValidationKeys) GetValidationKeys(context.Context) ([]*core_models.SecurityKeyInfo, error) {
	k.calls++
	return nil, errValidationKeysUnavailable
}

// recordingReferenceTokens counts how often access token validation looks a
// handle up, which it does for a reference handle only, and holds no token.
type recordingReferenceTokens struct {
	lookups int
}

func (s *recordingReferenceTokens) StoreReferenceToken(context.Context, string, *storage_models.Token) error {
	return errors.New("unexpected call")
}

func (s *recordingReferenceTokens) GetReferenceToken(context.Context, string) (*storage_models.Token, error) {
	s.lookups++
	return nil, storage.ErrNotFound
}

func (s *recordingReferenceTokens) RemoveReferenceToken(context.Context, string) error {
	return errors.New("unexpected call")
}

func (s *recordingReferenceTokens) RemoveReferenceTokens(context.Context, string, string) error {
	return errors.New("unexpected call")
}

func (s *recordingReferenceTokens) RemoveExpired(context.Context, time.Time) (int, error) {
	return 0, errors.New("unexpected call")
}

// The revocation endpoint refuses exactly the tokens access token validation
// reads as JWTs. This test ties the two together sample by sample: it fails
// when either side starts telling a JWT from a reference handle differently.
func TestTokenRevocationHandlerJwtFormMatchesAccessTokenValidation(t *testing.T) {
	t.Parallel()

	for name, token := range map[string]string{
		"three segments":            "aaa.bbb.ccc",
		"compact JWT":               jwtShapedToken,
		"two segments":              "a.b",
		"lone dot":                  ".",
		"trailing dot":              "a.",
		"leading dot":               ".a",
		"dot between spaces":        " . ",
		"default handle":            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		"unknown handle":            "does-not-exist",
		"handle with other symbols": "ab-cd_ef~gh+ij/kl=",
		"base64url without a dot":   "eyJhbGciOiJSUzI1NiJ9",
		"surrounding spaces":        " opaque ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			keys := &recordingValidationKeys{}
			referenceTokens := &recordingReferenceTokens{}
			tokenValidator := validators_impl.NewTokenValidator(
				slog.New(slog.NewTextHandler(io.Discard, nil)),
				config_options.NewWicketOptions(),
				nil,
				referenceTokens,
				nil,
				nil,
				nil,
				keys,
				nil,
				nil,
			)
			_, validationErr := tokenValidator.ValidateAccessToken(context.Background(), token, "")
			if keys.calls+referenceTokens.lookups != 1 {
				t.Fatalf("access token validation asked for keys %d times and looked up a handle %d times, want exactly one of the two once", keys.calls, referenceTokens.lookups)
			}
			validatedAsJwt := keys.calls == 1
			if validatedAsJwt != errors.Is(validationErr, errValidationKeysUnavailable) {
				t.Fatalf("access token validation error = %v with keys asked %d times", validationErr, keys.calls)
			}

			result := validRevocationResult("")
			result.Token = token
			out := runRevocationWith(
				revocationRequest(http.MethodPost, "", url.Values{"token": {token}}.Encode()),
				revocationSetup{
					clientResult: authenticatedRevocationClient(),
					validator:    &fakeRevocationRequestValidator{result: result},
				},
			)
			if out.err != nil {
				t.Fatalf("Process error = %v", out.err)
			}
			refused := out.recorder.Code == http.StatusBadRequest
			if refused {
				if got := decodeRevocationError(t, out.recorder)["error"]; got != wicket.RevocationErrorsUnsupportedTokenType.Error() {
					t.Fatalf("error = %v, want unsupported_token_type", got)
				}
			} else if out.recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 400 or 200", out.recorder.Code)
			}
			if refused == out.generator.called {
				t.Fatalf("status = %d but revocation reached = %v", out.recorder.Code, out.generator.called)
			}

			if refused != validatedAsJwt {
				t.Fatalf("revocation refused the token = %v, access token validation read it as a JWT = %v", refused, validatedAsJwt)
			}
		})
	}
}
