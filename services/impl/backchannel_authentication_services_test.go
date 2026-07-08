// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonewx/wicket/storage/models"
)

func TestBackchannelAuthenticationNotificationServiceTable(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		statusCode int
		request    func(string) *models.BackchannelAuthenticationRequest
		wantErr    bool
		wantCall   bool
	}{
		{
			name:       "sends auth request id with bearer notification token",
			statusCode: http.StatusNoContent,
			request: func(endpoint string) *models.BackchannelAuthenticationRequest {
				return &models.BackchannelAuthenticationRequest{
					RequestId:                  "auth-request-id",
					ClientNotificationEndpoint: endpoint,
					ClientNotificationToken:    "notification-token",
				}
			},
			wantCall: true,
		},
		{
			name:       "skips empty endpoint",
			statusCode: http.StatusNoContent,
			request: func(string) *models.BackchannelAuthenticationRequest {
				return &models.BackchannelAuthenticationRequest{RequestId: "auth-request-id"}
			},
		},
		{
			name:       "returns error for failed notification endpoint",
			statusCode: http.StatusBadGateway,
			request: func(endpoint string) *models.BackchannelAuthenticationRequest {
				return &models.BackchannelAuthenticationRequest{
					RequestId:                  "auth-request-id",
					ClientNotificationEndpoint: endpoint,
					ClientNotificationToken:    "notification-token",
				}
			},
			wantErr:  true,
			wantCall: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			method := ""
			authorization := ""
			authReqID := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				method = r.Method
				authorization = r.Header.Get("authorization")
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode body: %v", err)
				}
				authReqID = body["auth_req_id"]
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			err := NewBackchannelAuthenticationNotificationService(server.Client()).Notify(tt.request(server.URL))
			if tt.wantErr && err == nil {
				t.Fatal("error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("notify: %v", err)
			}
			if tt.wantErr && err.Error() != "backchannel authentication notification failed" {
				t.Fatalf("error = %v", err)
			}
			if tt.wantCall && calls != 1 {
				t.Fatalf("calls = %d, want 1", calls)
			}
			if !tt.wantCall && calls != 0 {
				t.Fatalf("calls = %d, want 0", calls)
			}
			if tt.wantCall {
				if method != http.MethodPost {
					t.Fatalf("method = %s, want POST", method)
				}
				if authorization != "Bearer notification-token" {
					t.Fatalf("authorization = %q", authorization)
				}
				if authReqID != "auth-request-id" {
					t.Fatalf("auth_req_id = %q", authReqID)
				}
			}
		})
	}
}
