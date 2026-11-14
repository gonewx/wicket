// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteClientAuthenticationUnavailable(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeClientAuthenticationUnavailable(recorder)

	response := recorder.Result()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", response.StatusCode)
	}
	if got := recorder.Body.String(); got != "Internal Server Error\n" || len(got) != 22 {
		t.Fatalf("body %q", got)
	}
	want := map[string]string{
		"Cache-Control": "no-store",
		"Content-Type":  "text/plain; charset=utf-8",
	}
	if len(response.Header) != len(want) {
		t.Fatalf("unexpected headers: %v", response.Header)
	}
	for name, value := range want {
		if got := response.Header.Values(name); len(got) != 1 || got[0] != value {
			t.Fatalf("header %s = %v, want %q", name, got, value)
		}
	}
}
