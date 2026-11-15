// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/clientassertion"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const pushTestSecret = "push-secret"

// pushClientValidator authenticates "push.client" by the secret in the form.
type pushClientValidator struct{ unavailable bool }

func (v pushClientValidator) Validate(r *http.Request) *validators_models.ClientSecretValidationResult {
	result := validators_models.NewClientSecretValidationResult()
	if v.unavailable {
		result.Error = clientassertion.ErrAuthenticationUnavailable
		return result
	}
	if r.PostForm.Get("client_secret") != pushTestSecret {
		result.Error = wicket.TokenErrorsInvalidClient
		return result
	}
	client := storage_models.NewClient()
	client.ClientId = "push.client"
	result.Client = client
	return result
}

// pushRequestValidator records what it validates and answers with err.
type pushRequestValidator struct {
	err    error
	values url.Values
	phase  validators.AuthorizeRequestPhase
}

func (v *pushRequestValidator) Validate(_ context.Context, values url.Values, _ *claims.ClaimsPrincipal, phase validators.AuthorizeRequestPhase) *validators_models.AuthorizeRequestValidationResult {
	v.values = values
	v.phase = phase
	values.Set("mutated_by_validator", "x")
	return validators_models.NewAuthorizeRequestValidationResultWithErr(validators_models.NewValidatedAuthorizeRequest(), v.err, "")
}

// pushRecorder stores pushes.
type pushRecorder struct {
	err        error
	parameters url.Values
	client     string
}

func (p *pushRecorder) Push(_ context.Context, client *storage_models.Client, parameters url.Values) (string, int, error) {
	if p.err != nil {
		return "", 0, p.err
	}
	p.parameters = parameters
	p.client = client.ClientId
	return "urn:ietf:params:oauth:request_uri:pushed", 60, nil
}

func TestPushedAuthorizationRequestHandler(t *testing.T) {
	t.Parallel()

	form := func(extra string) string {
		return "client_secret=" + pushTestSecret + "&response_type=code&redirect_uri=https%3A%2F%2Frp%2Fcb&scope=openid" + extra
	}
	tests := map[string]struct {
		method       string
		contentType  string
		body         string
		unavailable  bool
		validatorErr error
		pushErr      error
		wantStatus   int
		wantError    string
		// wantDescription says whether error_description is present.
		wantDescription bool
		wantStored      bool
	}{
		"get":                {method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed},
		"not a form":         {contentType: "application/json", body: "{}", wantStatus: http.StatusUnsupportedMediaType},
		"no authentication":  {body: "response_type=code", wantStatus: http.StatusBadRequest, wantError: "invalid_client"},
		"wrong secret":       {body: "client_secret=wrong", wantStatus: http.StatusBadRequest, wantError: "invalid_client"},
		"store unavailable":  {body: form(""), unavailable: true, wantStatus: http.StatusInternalServerError},
		"other client_id":    {body: form("&client_id=other"), wantStatus: http.StatusBadRequest, wantError: "invalid_request", wantDescription: true},
		"two client_ids":     {body: form("&client_id=push.client&client_id=push.client"), wantStatus: http.StatusBadRequest, wantError: "invalid_request", wantDescription: true},
		"invalid parameters": {body: form(""), validatorErr: wicket.AuthorizeErrorsInvalidRequest, wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		"invalid scope":      {body: form(""), validatorErr: wicket.AuthorizeErrorsInvalidScope, wantStatus: http.StatusBadRequest, wantError: "invalid_scope"},
		"validator failure":  {body: form(""), validatorErr: wicket.AuthorizeErrorsServerError, wantStatus: http.StatusInternalServerError},
		"store failure":      {body: form(""), pushErr: errors.New("boom"), wantStatus: http.StatusInternalServerError},
		"pushed":             {body: form(""), wantStatus: http.StatusCreated, wantStored: true},
		"pushed with own id": {body: form("&client_id=push.client"), wantStatus: http.StatusCreated, wantStored: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			method := tc.method
			if method == "" {
				method = http.MethodPost
			}
			contentType := tc.contentType
			if contentType == "" {
				contentType = "application/x-www-form-urlencoded"
			}
			// The query string carries an authorization parameter that must
			// not reach the pushed request: only the body counts.
			request := httptest.NewRequest(method, "/connect/pushedauthorization?client_secret="+pushTestSecret+"&prompt=none", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", contentType)
			recorder := httptest.NewRecorder()
			validator := &pushRequestValidator{err: tc.validatorErr}
			pusher := &pushRecorder{err: tc.pushErr}
			handler := NewPushedAuthorizationRequestHandler(pushClientValidator{unavailable: tc.unavailable}, validator, pusher, nil)

			if err := handler.Process(recorder, request); err != nil {
				t.Fatalf("Process error = %v", err)
			}
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if tc.wantError != "" {
				var body map[string]string
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
					t.Fatalf("body %q: %v", recorder.Body.String(), err)
				}
				if body["error"] != tc.wantError {
					t.Fatalf("error = %q, want %q", body["error"], tc.wantError)
				}
				if _, present := body["error_description"]; present != tc.wantDescription && tc.wantError != "invalid_client" {
					t.Fatalf("error_description present = %v, want %v (%s)", present, tc.wantDescription, recorder.Body.String())
				}
			}
			if !tc.wantStored {
				if pusher.parameters != nil {
					t.Fatal("parameters stored although the push failed")
				}
				return
			}
			if validator.phase != validators.AuthorizeRequestPhasePush {
				t.Fatalf("validated in phase %d, want Push", validator.phase)
			}
			if got := recorder.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := recorder.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") || !strings.Contains(got, "no-cache") {
				t.Errorf("Cache-Control = %q", got)
			}
			var body struct {
				RequestUri string `json:"request_uri"`
				ExpiresIn  int    `json:"expires_in"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.RequestUri != "urn:ietf:params:oauth:request_uri:pushed" || body.ExpiresIn != 60 {
				t.Fatalf("body = %+v", body)
			}
			if pusher.client != "push.client" {
				t.Errorf("pushed for %q", pusher.client)
			}
			stored := pusher.parameters
			if stored.Get(wicket.AuthorizeRequestClientId) != "push.client" {
				t.Errorf("stored client_id = %v", stored[wicket.AuthorizeRequestClientId])
			}
			for _, name := range []string{"client_secret", "client_assertion", "client_assertion_type", "mutated_by_validator", wicket.AuthorizeRequestPrompt} {
				if stored.Has(name) {
					t.Errorf("stored parameters carry %s", name)
				}
			}
			if stored.Get(wicket.AuthorizeRequestRedirectUri) != "https://rp/cb" {
				t.Errorf("stored parameters = %v", stored)
			}
		})
	}
}
