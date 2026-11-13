// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackChannelLogoutHttpClientDefaultsToBoundedNonRedirectingClient(t *testing.T) {
	cfg := &ServerConfig{}

	client := cfg.BackChannelLogoutHttpClient()

	if client == nil {
		t.Fatal("expected a default client when the host injects none")
	}
	if client.Timeout != 5*time.Second {
		t.Fatalf("timeout = %v, want 5s", client.Timeout)
	}

	var forwarded atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
	}))
	defer elsewhere.Close()
	registered := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer registered.Close()

	response, err := client.PostForm(registered.URL, url.Values{"logout_token": {"token"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want the redirect itself (307)", response.StatusCode)
	}
	if forwarded.Load() != 0 {
		t.Fatal("the logout token was forwarded to the redirect target")
	}
}

func TestBackChannelLogoutHttpClientKeepsTheHostClient(t *testing.T) {
	host := &http.Client{Timeout: time.Second}
	cfg := &ServerConfig{}
	cfg.SetBackChannelLogoutHttpClient(host)

	if cfg.BackChannelLogoutHttpClient() != host {
		t.Fatal("expected the host-provided client to be returned as is")
	}
}

func TestBackChannelLogoutHttpClientOnNilConfigIsNil(t *testing.T) {
	var cfg *ServerConfig
	if cfg.BackChannelLogoutHttpClient() != nil {
		t.Fatal("expected nil from a nil config")
	}
}
