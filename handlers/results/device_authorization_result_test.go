// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	responses_models "github.com/gonewx/wicket/responses/models"
)

func executeDeviceAuthorizationResult(t *testing.T, response *responses_models.DeviceAuthorizationResponse) (*http.Response, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/deviceauthorization", nil)
	if err := NewDeviceAuthorizationResult(response).Execute(recorder, request); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Result reports the headers as they stood when the status line was
	// written, which is what reaches the client.
	result := recorder.Result()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", recorder.Body.String(), err)
	}
	return result, body
}

func TestDeviceAuthorizationResultWritesJson(t *testing.T) {
	result, body := executeDeviceAuthorizationResult(t, &responses_models.DeviceAuthorizationResponse{
		DeviceCode:              "device",
		UserCode:                "123456789",
		VerificationUri:         "https://wicket.test/device",
		VerificationUriComplete: "https://wicket.test/device?userCode=123456789",
		DeviceCodeLifetime:      300,
		Interval:                5,
	})

	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.StatusCode)
	}
	if got := result.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	cacheControl := strings.Join(result.Header.Values("Cache-Control"), ",")
	if !strings.Contains(cacheControl, "no-store") || result.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("no-cache headers missing: Cache-Control=%q Pragma=%q", cacheControl, result.Header.Get("Pragma"))
	}
	for key, want := range map[string]any{
		"device_code":               "device",
		"user_code":                 "123456789",
		"verification_uri":          "https://wicket.test/device",
		"verification_uri_complete": "https://wicket.test/device?userCode=123456789",
		"expires_in":                float64(300),
		"interval":                  float64(5),
	} {
		if body[key] != want {
			t.Fatalf("%s = %v, want %v", key, body[key], want)
		}
	}
}

func TestDeviceAuthorizationResultOmitsEmptyCompleteUri(t *testing.T) {
	_, body := executeDeviceAuthorizationResult(t, &responses_models.DeviceAuthorizationResponse{
		DeviceCode:         "device",
		UserCode:           "123456789",
		VerificationUri:    "https://wicket.test/device",
		DeviceCodeLifetime: 300,
		Interval:           5,
	})

	if _, present := body["verification_uri_complete"]; present {
		t.Fatalf("verification_uri_complete present for an empty value: %v", body)
	}
	if body["verification_uri"] != "https://wicket.test/device" {
		t.Fatalf("verification_uri = %v", body["verification_uri"])
	}
}
