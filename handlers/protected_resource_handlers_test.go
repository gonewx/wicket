// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type fakeApiSecretValidator struct {
	result *validators_models.ApiSecretValidationResult
}

func (v *fakeApiSecretValidator) Validate(*http.Request) *validators_models.ApiSecretValidationResult {
	return v.result
}

type fakeIntrospectionRequestValidator struct {
	result *validators_models.IntrospectionRequestValidationResult
	err    error
}

func (v *fakeIntrospectionRequestValidator) Validate(ctx context.Context, values url.Values, api *storage_models.ApiResource) (*validators_models.IntrospectionRequestValidationResult, error) {
	return v.result, v.err
}

type fakeIntrospectionResponseGenerator struct {
	entries map[string]any
}

func (g *fakeIntrospectionResponseGenerator) Handle(ctx context.Context, result *validators_models.IntrospectionRequestValidationResult) map[string]any {
	return g.entries
}

type fakeUserInfoRequestValidator struct {
	result *validators_models.UserInfoRequestValidationResult
}

func (v *fakeUserInfoRequestValidator) ValidateRequest(ctx context.Context, accessToken string) (*validators_models.UserInfoRequestValidationResult, error) {
	return v.result, nil
}

type fakeUserInfoResponseGenerator struct {
	claims map[string]any
	err    error
}

func (g *fakeUserInfoResponseGenerator) Handle(ctx context.Context, result *validators_models.UserInfoRequestValidationResult) (map[string]any, error) {
	return g.claims, g.err
}

func newIntrospectionForm(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/introspect", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func TestIntrospectionHandlerDispatch(t *testing.T) {
	t.Parallel()

	okApi := validators_models.NewApiSecretValidationResult()

	for name, tt := range map[string]struct {
		request       *http.Request
		apiResult     *validators_models.ApiSecretValidationResult
		requestResult *validators_models.IntrospectionRequestValidationResult
		entries       map[string]any
		wantStatus    int
		wantActive    *bool
	}{
		"GET returns 405": {
			request:    httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/introspect", nil),
			wantStatus: http.StatusMethodNotAllowed,
		},
		"JSON content type returns 415": {
			request: func() *http.Request {
				request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/introspect", strings.NewReader("{}"))
				request.Header.Set("Content-Type", "application/json")
				return request
			}(),
			wantStatus: http.StatusUnsupportedMediaType,
		},
		"nil api result returns 401": {
			request:    newIntrospectionForm("token=abc"),
			apiResult:  nil,
			wantStatus: http.StatusUnauthorized,
		},
		"failed api authentication returns 401": {
			request: newIntrospectionForm("token=abc"),
			apiResult: func() *validators_models.ApiSecretValidationResult {
				result := validators_models.NewApiSecretValidationResult()
				result.Error = gois.TokenErrorsInvalidRequest
				return result
			}(),
			wantStatus: http.StatusUnauthorized,
		},
		"validation error returns 400": {
			request:   newIntrospectionForm(""),
			apiResult: okApi,
			requestResult: func() *validators_models.IntrospectionRequestValidationResult {
				result := validators_models.NewIntrospectionRequestValidationResult()
				result.Error = gois.TokenErrorsInvalidRequest
				return result
			}(),
			wantStatus: http.StatusBadRequest,
		},
		"inactive token still returns 200": {
			request:       newIntrospectionForm("token=unknown"),
			apiResult:     okApi,
			requestResult: validators_models.NewIntrospectionRequestValidationResult(),
			entries:       map[string]any{"active": false},
			wantStatus:    http.StatusOK,
			wantActive:    boolPtr(false),
		},
		"active token returns the generated entries": {
			request:       newIntrospectionForm("token=known"),
			apiResult:     okApi,
			requestResult: validators_models.NewIntrospectionRequestValidationResult(),
			entries:       map[string]any{"active": true, "scope": "api1"},
			wantStatus:    http.StatusOK,
			wantActive:    boolPtr(true),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := NewIntrospectionHandler(
				&fakeApiSecretValidator{result: tt.apiResult},
				&fakeIntrospectionRequestValidator{result: tt.requestResult},
				&fakeIntrospectionResponseGenerator{entries: tt.entries},
				quietLogger(),
			)
			recorder := httptest.NewRecorder()
			if err := handler.Process(recorder, tt.request); err != nil {
				t.Fatalf("Process: %v", err)
			}
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if tt.wantActive != nil {
				var body map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
					t.Fatalf("unmarshal body: %v", err)
				}
				if body["active"] != *tt.wantActive {
					t.Fatalf("active = %v, want %v", body["active"], *tt.wantActive)
				}
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }

func newUserInfoHandlerUnderTest(validationResult *validators_models.UserInfoRequestValidationResult, generated map[string]any) *UserInfoHandler {
	return NewUserInfoHandler(
		validators_impl.NewBearerTokenUsageValidator(quietLogger()),
		&fakeUserInfoRequestValidator{result: validationResult},
		&fakeUserInfoResponseGenerator{claims: generated},
		config_options.NewWicketOptions(),
		quietLogger(),
	)
}

func TestUserInfoHandlerDispatch(t *testing.T) {
	t.Parallel()

	success := validators_models.NewUserInfoRequestValidationResult()
	success.Subject = claims.NewClaimsPrincipal()

	t.Run("missing bearer token returns 401 with a challenge header", func(t *testing.T) {
		t.Parallel()
		handler := newUserInfoHandlerUnderTest(success, nil)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/userinfo", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", recorder.Code)
		}
		if len(recorder.Header()["www-authenticate"]) == 0 {
			t.Fatal("missing WWW-Authenticate challenge")
		}
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		t.Parallel()
		invalid := validators_models.NewUserInfoRequestValidationResult()
		invalid.Error = gois.ProtectedResourceErrorsInvalidToken
		handler := newUserInfoHandlerUnderTest(invalid, nil)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/userinfo", nil)
		request.Header.Set("Authorization", "Bearer not-a-token")
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", recorder.Code)
		}
	})

	t.Run("insufficient scope returns 403", func(t *testing.T) {
		t.Parallel()
		forbidden := validators_models.NewUserInfoRequestValidationResult()
		forbidden.Error = gois.ProtectedResourceErrorsInsufficientScope
		handler := newUserInfoHandlerUnderTest(forbidden, nil)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/userinfo", nil)
		request.Header.Set("Authorization", "Bearer token-without-openid")
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", recorder.Code)
		}
	})

	t.Run("valid token returns the filtered claims", func(t *testing.T) {
		t.Parallel()
		handler := newUserInfoHandlerUnderTest(success, map[string]any{"sub": "subject-1", "email": "subject@wicket.test"})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/userinfo", nil)
		request.Header.Set("Authorization", "Bearer good-token")
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", recorder.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if body["sub"] != "subject-1" {
			t.Fatalf("sub = %v, want subject-1", body["sub"])
		}
	})

	t.Run("POST body token is accepted", func(t *testing.T) {
		t.Parallel()
		handler := newUserInfoHandlerUnderTest(success, map[string]any{"sub": "subject-1"})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/userinfo", strings.NewReader("access_token=good-token"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", recorder.Code)
		}
	})

	t.Run("PUT returns 405", func(t *testing.T) {
		t.Parallel()
		handler := newUserInfoHandlerUnderTest(success, nil)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, "https://wicket.test/connect/userinfo", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", recorder.Code)
		}
	})
}
