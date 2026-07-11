// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type fakeClientSecretValidator struct {
	result *validators_models.ClientSecretValidationResult
}

func (v *fakeClientSecretValidator) Validate(*http.Request) *validators_models.ClientSecretValidationResult {
	return v.result
}

type fakeTokenRequestValidator struct {
	result *validators_models.TokenRequestValidationResult
}

func (v *fakeTokenRequestValidator) ValidateRequest(url.Values, *validators_models.ClientSecretValidationResult) *validators_models.TokenRequestValidationResult {
	return v.result
}

type fakeTokenResponseGenerator struct {
	response *responses_models.TokenResponse
	err      error
}

func (g *fakeTokenResponseGenerator) Handle(*validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	return g.response, g.err
}

func newTokenForm() *http.Request {
	body := url.Values{gois.TokenRequestGrantType: {gois.GrantTypeClientCredentials}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "https://wicket.test"+gois.ProtocolRoutePathsToken, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func successClientResult() *validators_models.ClientSecretValidationResult {
	return validators_models.NewClientSecretValidationResult()
}

func TestTokenHandlerProcessDispatch(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		request       func() *http.Request
		clientResult  *validators_models.ClientSecretValidationResult
		requestResult *validators_models.TokenRequestValidationResult
		generated     *responses_models.TokenResponse
		wantStatus    int
		wantError     string
		wantTokenType string
	}{
		"client authentication failure returns invalid_client": {
			request: newTokenForm,
			clientResult: func() *validators_models.ClientSecretValidationResult {
				result := validators_models.NewClientSecretValidationResult()
				result.Error = gois.TokenErrorsInvalidClient
				return result
			}(),
			wantStatus: http.StatusBadRequest,
			wantError:  gois.TokenErrorsInvalidClient.Error(),
		},
		"nil client result returns invalid_client": {
			request:      newTokenForm,
			clientResult: nil,
			wantStatus:   http.StatusBadRequest,
			wantError:    gois.TokenErrorsInvalidClient.Error(),
		},
		"request validation error returns its standard error": {
			request:      newTokenForm,
			clientResult: successClientResult(),
			requestResult: validators_models.NewTokenRequestValidationResult(
				validators_models.NewValidatedTokenRequest(),
				validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsInvalidGrant),
			),
			wantStatus: http.StatusBadRequest,
			wantError:  gois.TokenErrorsInvalidGrant.Error(),
		},
		"successful issuance returns bearer token response": {
			request:       newTokenForm,
			clientResult:  successClientResult(),
			requestResult: validators_models.NewTokenRequestValidationResult(validators_models.NewValidatedTokenRequest()),
			generated: &responses_models.TokenResponse{
				AccessToken:         "opaque-access-token",
				AccessTokenLifetime: 3600,
			},
			wantStatus:    http.StatusOK,
			wantTokenType: responses_models.BearerTokenType,
		},
		"control byte in form payload returns invalid_request": {
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "https://wicket.test"+gois.ProtocolRoutePathsToken, strings.NewReader("grant_type=client_credentials&scope=%00"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			clientResult: successClientResult(),
			wantStatus:   http.StatusBadRequest,
			wantError:    gois.TokenErrorsInvalidRequest.Error(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := NewTokenHandler(
				&fakeClientSecretValidator{result: tt.clientResult},
				&fakeTokenRequestValidator{result: tt.requestResult},
				&fakeTokenResponseGenerator{response: tt.generated},
				nil,
			)
			rec := httptest.NewRecorder()
			if err := handler.Process(rec, tt.request()); err != nil {
				t.Fatalf("process: %v", err)
			}
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if tt.wantError != "" {
				if body["error"] != tt.wantError {
					t.Fatalf("error = %v, want %v", body["error"], tt.wantError)
				}
			}
			if tt.wantTokenType != "" {
				if body["token_type"] != tt.wantTokenType {
					t.Fatalf("token_type = %v, want %v", body["token_type"], tt.wantTokenType)
				}
				if body["access_token"] != "opaque-access-token" {
					t.Fatalf("access_token = %v", body["access_token"])
				}
			}
		})
	}
}
