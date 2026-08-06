// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type cibaHandlerClientValidator struct {
	result *validators_models.ClientSecretValidationResult
}

func (v cibaHandlerClientValidator) Validate(*http.Request) *validators_models.ClientSecretValidationResult {
	return v.result
}

type cibaHandlerRequestValidator struct {
	result *validators_models.BackchannelAuthenticationRequestValidationResult
}

func (v cibaHandlerRequestValidator) Validate(ctx context.Context, parameters url.Values, client *storage_models.Client) *validators_models.BackchannelAuthenticationRequestValidationResult {
	return v.result
}

func TestBackchannelAuthenticationHandlerProcessTable(t *testing.T) {
	t.Parallel()

	client := storage_models.NewClient()
	client.ClientId = "client"
	successClient := validators_models.NewClientSecretValidationResult()
	successClient.Client = client

	successValidation := validators_models.NewBackchannelAuthenticationRequestValidationResult()
	successValidation.Request = &storage_models.BackchannelAuthenticationRequest{RequestId: "opaque-request-id"}
	successValidation.ExpiresIn = 300
	successValidation.Interval = 5

	for name, tt := range map[string]struct {
		clientResult  *validators_models.ClientSecretValidationResult
		requestResult *validators_models.BackchannelAuthenticationRequestValidationResult
		wantStatus    int
		wantError     error
	}{
		"success writes CIBA authentication response": {
			clientResult:  successClient,
			requestResult: successValidation,
			wantStatus:    http.StatusOK,
		},
		"client authentication failure writes standard error": {
			clientResult: func() *validators_models.ClientSecretValidationResult {
				result := validators_models.NewClientSecretValidationResult()
				result.Error = gois.TokenErrorsInvalidClient
				return result
			}(),
			requestResult: successValidation,
			wantStatus:    http.StatusBadRequest,
			wantError:     gois.TokenErrorsInvalidClient,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := NewBackchannelAuthenticationHandler(
				cibaHandlerClientValidator{result: tt.clientResult},
				cibaHandlerRequestValidator{result: tt.requestResult},
			)
			req := httptest.NewRequest(http.MethodPost, "/connect/ciba", nil)
			rec := httptest.NewRecorder()

			if err := handler.Process(rec, req); err != nil {
				t.Fatalf("process: %v", err)
			}
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if tt.wantError != nil {
				if body["error"] != tt.wantError.Error() {
					t.Fatalf("error = %v, want %v", body["error"], tt.wantError)
				}
				return
			}
			if body["auth_req_id"] != "opaque-request-id" {
				t.Fatalf("auth_req_id = %v", body["auth_req_id"])
			}
			if body["expires_in"] != float64(300) || body["interval"] != float64(5) {
				t.Fatalf("response = %#v", body)
			}
		})
	}
}
