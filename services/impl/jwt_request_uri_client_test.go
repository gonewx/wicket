// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	config_options "github.com/gonewx/wicket/config/options"
)

func TestJwtRequestUriHttpClientGetJwt(t *testing.T) {
	t.Parallel()

	options := config_options.NewWicketOptions()

	t.Run("returns the response body on 200", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("header.payload.signature"))
		}))
		t.Cleanup(server.Close)

		client := NewJwtRequestUriHttpClient(server.Client(), options)
		body, err := client.GetJwt(server.URL+"/request.jwt", nil)
		if err != nil {
			t.Fatalf("GetJwt: %v", err)
		}
		if body != "header.payload.signature" {
			t.Fatalf("body = %q, want the served request object", body)
		}
	})

	t.Run("rejects a non-2xx response", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(server.Close)

		client := NewJwtRequestUriHttpClient(server.Client(), options)
		if _, err := client.GetJwt(server.URL+"/request.jwt", nil); err == nil {
			t.Fatal("GetJwt accepted a 404 response")
		}
	})

	t.Run("rejects a body over the configured JWT limit", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("a", options.InputLengthRestrictions.Jwt+1)))
		}))
		t.Cleanup(server.Close)

		client := NewJwtRequestUriHttpClient(server.Client(), options)
		if _, err := client.GetJwt(server.URL+"/request.jwt", nil); err == nil {
			t.Fatal("GetJwt accepted an oversized response body")
		}
	})

	t.Run("surfaces transport errors", func(t *testing.T) {
		t.Parallel()
		client := NewJwtRequestUriHttpClient(nil, options)
		if _, err := client.GetJwt("http://127.0.0.1:1/request.jwt", nil); err == nil {
			t.Fatal("GetJwt accepted an unreachable host")
		}
	})
}
