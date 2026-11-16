// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	responses_models "github.com/gonewx/wicket/responses/models"
)

func executeTokenError(t *testing.T, response *responses_models.TokenErrorResponse) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	if err := NewTokenErrorResult(response).Execute(recorder, httptest.NewRequest(http.MethodPost, "/connect/token", nil)); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", recorder.Body.String(), err)
	}
	return recorder, body
}

func TestTokenErrorResultIsJsonAndNotCached(t *testing.T) {
	t.Parallel()
	recorder, body := executeTokenError(t, &responses_models.TokenErrorResponse{
		Error:            errors.New("invalid_grant"),
		ErrorDescription: "code expired",
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type %q", got)
	}
	if got := recorder.Header().Values("Cache-Control"); len(got) == 0 || got[0] != "no-store" {
		t.Fatalf("cache control %q", got)
	}
	if body["error"] != "invalid_grant" || body["error_description"] != "code expired" || len(body) != 2 {
		t.Fatalf("body %v", body)
	}
}

func TestTokenErrorResultLeavesOutAnEmptyDescription(t *testing.T) {
	t.Parallel()
	_, body := executeTokenError(t, &responses_models.TokenErrorResponse{Error: errors.New("invalid_client")})
	if _, ok := body["error_description"]; ok || body["error"] != "invalid_client" || len(body) != 1 {
		t.Fatalf("body %v", body)
	}
}

func TestTokenErrorResultWritesCustomEntriesBesideTheError(t *testing.T) {
	t.Parallel()
	_, body := executeTokenError(t, &responses_models.TokenErrorResponse{
		Error:  errors.New("invalid_grant"),
		Custom: map[string]any{"interval": float64(5), "error": "overridden"},
	})
	if body["interval"] != float64(5) || body["error"] != "invalid_grant" {
		t.Fatalf("body %v", body)
	}
	if _, ok := body["custom"]; ok {
		t.Fatalf("body %v", body)
	}
}

func TestTokenErrorResultCustomDescription(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		coreDescription string
		custom          any
		want            string
		present         bool
	}{
		"dropped when the core has none":       {coreDescription: "", custom: "custom description"},
		"empty dropped when the core has none": {coreDescription: "", custom: ""},
		"non-string dropped":                   {coreDescription: "", custom: 42},
		"core description wins":                {coreDescription: "code expired", custom: "custom description", want: "code expired", present: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, body := executeTokenError(t, &responses_models.TokenErrorResponse{
				Error:            errors.New("invalid_grant"),
				ErrorDescription: tc.coreDescription,
				Custom:           map[string]any{"error_description": tc.custom, "extra": "kept"},
			})
			description, present := body["error_description"]
			if present != tc.present || (present && description != tc.want) {
				t.Fatalf("error_description in body %v", body)
			}
			if body["error"] != "invalid_grant" || body["extra"] != "kept" {
				t.Fatalf("body %v", body)
			}
		})
	}
}
