// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	responses_models "github.com/gonewx/wicket/responses/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type fakeDeviceAuthorizationRequestValidator struct {
	result       *validators_models.DeviceAuthorizationRequestValidationResult
	called       bool
	parameters   url.Values
	clientResult *validators_models.ClientSecretValidationResult
}

func (v *fakeDeviceAuthorizationRequestValidator) ValidateRequest(ctx context.Context, parameters url.Values, clientResult *validators_models.ClientSecretValidationResult) *validators_models.DeviceAuthorizationRequestValidationResult {
	v.called = true
	v.parameters = parameters
	v.clientResult = clientResult
	return v.result
}

type fakeDeviceAuthorizationResponseGenerator struct {
	response *responses_models.DeviceAuthorizationResponse
	err      error
	called   bool
	baseUrl  string
}

func (g *fakeDeviceAuthorizationResponseGenerator) Handle(ctx context.Context, result *validators_models.DeviceAuthorizationRequestValidationResult, baseUrl string) (*responses_models.DeviceAuthorizationResponse, error) {
	g.called = true
	g.baseUrl = baseUrl
	return g.response, g.err
}

func deviceClientResult() *validators_models.ClientSecretValidationResult {
	client := storage_models.NewClient()
	client.ClientId = "device.client"
	result := validators_models.NewClientSecretValidationResult()
	result.Client = client
	return result
}

func deviceValidation(err error) *validators_models.DeviceAuthorizationRequestValidationResult {
	request := validators_models.NewValidatedDeviceAuthorizationRequest()
	if err == nil {
		return validators_models.NewDeviceAuthorizationRequestValidationResult(request)
	}
	return validators_models.NewDeviceAuthorizationRequestValidationResult(request,
		validators_models.WithDeviceAuthorizationRequestValidationResultError(err),
		validators_models.WithDeviceAuthorizationRequestValidationResultDescription("detail"),
	)
}

func deviceRequest(method string, target string, body string) *http.Request {
	req := httptest.NewRequest(method, "https://wicket.test"+wicket.ProtocolRoutePathsDeviceAuthorization+target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

type deviceOutcome struct {
	recorder  *httptest.ResponseRecorder
	err       error
	validator *fakeDeviceAuthorizationRequestValidator
	generator *fakeDeviceAuthorizationResponseGenerator
	logs      string
}

type deviceSetup struct {
	disabled     bool
	clientResult *validators_models.ClientSecretValidationResult
	validator    *fakeDeviceAuthorizationRequestValidator
	generator    *fakeDeviceAuthorizationResponseGenerator
}

func runDeviceAuthorization(req *http.Request, setup deviceSetup) deviceOutcome {
	if setup.validator == nil {
		setup.validator = &fakeDeviceAuthorizationRequestValidator{result: deviceValidation(nil)}
	}
	if setup.generator == nil {
		setup.generator = &fakeDeviceAuthorizationResponseGenerator{response: &responses_models.DeviceAuthorizationResponse{
			DeviceCode:         "secret-device-code",
			UserCode:           "secret-user-code",
			VerificationUri:    "https://wicket.test/device",
			DeviceCodeLifetime: 300,
			Interval:           5,
		}}
	}
	options := config_options.NewWicketOptions()
	options.Endpoints.EnableDeviceAuthorizationEndpoint = !setup.disabled

	var logs bytes.Buffer
	handler := NewDeviceAuthorizationHandler(
		&fakeClientSecretValidator{result: setup.clientResult},
		setup.validator,
		setup.generator,
		&fakeServerUrls{base: "https://wicket.test"},
		options,
		slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	)
	recorder := httptest.NewRecorder()
	err := handler.Process(recorder, req)
	return deviceOutcome{recorder: recorder, err: err, validator: setup.validator, generator: setup.generator, logs: logs.String()}
}

func decodeDeviceBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", recorder.Body.String(), err)
	}
	return body
}

func TestDeviceAuthorizationHandlerSwitchedOffIsNotFound(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			outcome := runDeviceAuthorization(deviceRequest(method, "", "client_id=device.client"), deviceSetup{disabled: true, clientResult: deviceClientResult()})

			if outcome.err != nil {
				t.Fatalf("Process: %v", outcome.err)
			}
			if outcome.recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", outcome.recorder.Code)
			}
			if outcome.validator.called || outcome.generator.called {
				t.Fatal("a switched-off endpoint must not process the request")
			}
		})
	}
}

func TestDeviceAuthorizationHandlerRequestShape(t *testing.T) {
	cases := map[string]struct {
		request *http.Request
		status  int
	}{
		"GET": {request: deviceRequest(http.MethodGet, "", ""), status: http.StatusMethodNotAllowed},
		"PUT": {request: deviceRequest(http.MethodPut, "", "client_id=device.client"), status: http.StatusMethodNotAllowed},
		"JSON": {request: func() *http.Request {
			req := deviceRequest(http.MethodPost, "", `{"client_id":"device.client"}`)
			req.Header.Set("Content-Type", "application/json")
			return req
		}(), status: http.StatusUnsupportedMediaType},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			outcome := runDeviceAuthorization(tc.request, deviceSetup{clientResult: deviceClientResult()})

			if outcome.err != nil {
				t.Fatalf("Process: %v", outcome.err)
			}
			if outcome.recorder.Code != tc.status {
				t.Fatalf("status = %d, want %d", outcome.recorder.Code, tc.status)
			}
			if outcome.validator.called {
				t.Fatal("validator called for a rejected request shape")
			}
		})
	}
}

func TestDeviceAuthorizationHandlerMalformedBodyIsInvalidRequest(t *testing.T) {
	outcome := runDeviceAuthorization(deviceRequest(http.MethodPost, "", "client_id=%zz"), deviceSetup{clientResult: deviceClientResult()})

	if outcome.err != nil {
		t.Fatalf("Process: %v", outcome.err)
	}
	if outcome.recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", outcome.recorder.Code)
	}
	if got := decodeDeviceBody(t, outcome.recorder)["error"]; got != "invalid_request" {
		t.Fatalf("error = %v, want invalid_request", got)
	}
}

func TestDeviceAuthorizationHandlerClientAuthenticationFailure(t *testing.T) {
	clientMissing := validators_models.NewClientSecretValidationResult()

	failures := map[string]*validators_models.ClientSecretValidationResult{
		"no result":        nil,
		"validation error": failedClientResult(wicket.TokenErrorsInvalidClient),
		"no client":        clientMissing,
	}
	for name, clientResult := range failures {
		t.Run(name+" without Authorization header", func(t *testing.T) {
			outcome := runDeviceAuthorization(deviceRequest(http.MethodPost, "", "client_id=device.client"), deviceSetup{clientResult: clientResult})

			if outcome.err != nil {
				t.Fatalf("Process: %v", outcome.err)
			}
			if outcome.recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", outcome.recorder.Code)
			}
			if got := outcome.recorder.Header().Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q, want none", got)
			}
			if got := decodeDeviceBody(t, outcome.recorder)["error"]; got != "invalid_client" {
				t.Fatalf("error = %v, want invalid_client", got)
			}
			if outcome.validator.called {
				t.Fatal("request validated for an unauthenticated client")
			}
		})
		t.Run(name+" with Basic header", func(t *testing.T) {
			req := deviceRequest(http.MethodPost, "", "")
			req.SetBasicAuth("device.client", "wrong")
			outcome := runDeviceAuthorization(req, deviceSetup{clientResult: clientResult})

			if outcome.err != nil {
				t.Fatalf("Process: %v", outcome.err)
			}
			if outcome.validator.called {
				t.Fatal("request validated for an unauthenticated client")
			}
			if outcome.recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", outcome.recorder.Code)
			}
			if got := outcome.recorder.Header().Get("WWW-Authenticate"); got != basicChallenge {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, basicChallenge)
			}
			if got := outcome.recorder.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", got)
			}
			if got := decodeDeviceBody(t, outcome.recorder)["error"]; got != "invalid_client" {
				t.Fatalf("error = %v, want invalid_client", got)
			}
		})
	}

	t.Run("Bearer header answers with the Bearer challenge", func(t *testing.T) {
		req := deviceRequest(http.MethodPost, "", "")
		req.Header.Set("Authorization", "Bearer x")
		outcome := runDeviceAuthorization(req, deviceSetup{clientResult: failedClientResult(wicket.TokenErrorsInvalidClient)})

		if outcome.err != nil {
			t.Fatalf("Process: %v", outcome.err)
		}
		if outcome.recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", outcome.recorder.Code)
		}
		if got := outcome.recorder.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
		}
		if outcome.validator.called {
			t.Fatal("request validated for an unauthenticated client")
		}
	})
}

func TestDeviceAuthorizationHandlerProtocolErrors(t *testing.T) {
	for _, protocolError := range []error{
		wicket.AuthorizeErrorsInvalidRequest,
		wicket.AuthorizeErrorsInvalidScope,
		wicket.AuthorizeErrorsUnauthorizedClient,
	} {
		t.Run(protocolError.Error(), func(t *testing.T) {
			validator := &fakeDeviceAuthorizationRequestValidator{result: deviceValidation(protocolError)}
			outcome := runDeviceAuthorization(deviceRequest(http.MethodPost, "", "client_id=device.client"), deviceSetup{clientResult: deviceClientResult(), validator: validator})

			if outcome.err != nil {
				t.Fatalf("Process: %v", outcome.err)
			}
			result := outcome.recorder.Result()
			if result.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", result.StatusCode)
			}
			if got := result.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", got)
			}
			if !strings.Contains(strings.Join(result.Header.Values("Cache-Control"), ","), "no-store") || result.Header.Get("Pragma") != "no-cache" {
				t.Fatalf("no-cache headers missing: %v", result.Header)
			}
			body := decodeDeviceBody(t, outcome.recorder)
			if len(body) != 1 || body["error"] != protocolError.Error() {
				t.Fatalf("body = %v, want only error %q", body, protocolError.Error())
			}
			if outcome.generator.called {
				t.Fatal("codes generated for a rejected request")
			}
		})
	}

	t.Run("wrapped protocol error keeps its code", func(t *testing.T) {
		wrapped := errors.Join(wicket.AuthorizeErrorsInvalidScope, errors.New("context"))
		validator := &fakeDeviceAuthorizationRequestValidator{result: deviceValidation(wrapped)}
		outcome := runDeviceAuthorization(deviceRequest(http.MethodPost, "", "client_id=device.client"), deviceSetup{clientResult: deviceClientResult(), validator: validator})

		if got := decodeDeviceBody(t, outcome.recorder)["error"]; got != "invalid_scope" {
			t.Fatalf("error = %v, want invalid_scope", got)
		}
	})
}

func TestDeviceAuthorizationHandlerReturnsInternalFailures(t *testing.T) {
	resourceFailure := errors.New("resource store unavailable")
	generatorFailure := errors.New("device store unavailable")

	cases := map[string]struct {
		setup deviceSetup
		want  error
	}{
		"validator without result": {
			setup: deviceSetup{validator: &fakeDeviceAuthorizationRequestValidator{}},
		},
		"validator non-protocol error": {
			setup: deviceSetup{validator: &fakeDeviceAuthorizationRequestValidator{result: deviceValidation(resourceFailure)}},
			want:  resourceFailure,
		},
		"generator error": {
			setup: deviceSetup{generator: &fakeDeviceAuthorizationResponseGenerator{err: generatorFailure}},
			want:  generatorFailure,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tc.setup.clientResult = deviceClientResult()
			outcome := runDeviceAuthorization(deviceRequest(http.MethodPost, "", "client_id=device.client"), tc.setup)

			if outcome.err == nil {
				t.Fatal("Process returned no error")
			}
			if tc.want != nil && (!errors.Is(outcome.err, tc.want) || outcome.err == tc.want) {
				t.Fatalf("error = %v, want %v wrapped", outcome.err, tc.want)
			}
			if outcome.recorder.Body.Len() != 0 {
				t.Fatalf("body written before returning the error: %q", outcome.recorder.Body.String())
			}
		})
	}
}

func TestDeviceAuthorizationHandlerSuccess(t *testing.T) {
	outcome := runDeviceAuthorization(
		deviceRequest(http.MethodPost, "?scope=from-query", "client_id=device.client&scope=api1"),
		deviceSetup{clientResult: deviceClientResult()},
	)

	if outcome.err != nil {
		t.Fatalf("Process: %v", outcome.err)
	}
	result := outcome.recorder.Result()
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.StatusCode)
	}
	if got := result.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	body := decodeDeviceBody(t, outcome.recorder)
	for _, key := range []string{"device_code", "user_code", "verification_uri", "expires_in", "interval"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("%s missing from %v", key, body)
		}
	}

	if got := outcome.validator.parameters.Get("scope"); got != "api1" {
		t.Fatalf("validator saw scope %q, want the body value api1", got)
	}
	if outcome.validator.clientResult == nil || outcome.validator.clientResult.Client.ClientId != "device.client" {
		t.Fatal("validator did not receive the authenticated client")
	}
	if outcome.generator.baseUrl != "https://wicket.test" {
		t.Fatalf("generator base URL = %q, want https://wicket.test", outcome.generator.baseUrl)
	}

	if strings.Contains(outcome.logs, "secret-device-code") || strings.Contains(outcome.logs, "secret-user-code") {
		t.Fatalf("codes written to the log: %s", outcome.logs)
	}
	if !strings.Contains(outcome.logs, "device.client") {
		t.Fatalf("client_id missing from the log: %s", outcome.logs)
	}
}
