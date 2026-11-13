// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	responses_models "github.com/gonewx/wicket/responses/models"
	storage_models "github.com/gonewx/wicket/storage/models"
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
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	recorder := httptest.NewRecorder()
	err := handler.Process(recorder, req)
	return revocationOutcome{recorder: recorder, err: err, validator: validator, generator: generator}
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
