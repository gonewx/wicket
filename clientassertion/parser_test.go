// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
)

func formRequest(values url.Values) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://server.example/connect/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func assertionValues(assertion string) url.Values {
	return url.Values{"client_assertion_type": {assertionType}, "client_assertion": {assertion}}
}

func TestParserWithoutAssertionParameters(t *testing.T) {
	parser := NewParser(Options{}, 100)
	secret, err := parser.Parse(formRequest(url.Values{"client_id": {"client"}, "client_secret": {"s"}}))
	if secret != nil || err != nil {
		t.Fatalf("got %+v, %v; want nil, nil", secret, err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://server.example/connect/token", strings.NewReader(`{"client_assertion":"x"}`))
	request.Header.Set("Content-Type", "application/json")
	if secret, err := parser.Parse(request); secret != nil || err != nil {
		t.Fatalf("non form body: got %+v, %v", secret, err)
	}
}

func TestParserReadsTheUnverifiedSubject(t *testing.T) {
	key := keyFor(t, "ES256", "k1")
	assertion := key.sign(t, "ES256", map[string]any{"sub": "client-from-sub"})
	values := assertionValues(assertion)
	values.Set("client_id", "client-from-form")
	secret, err := NewParser(Options{}, 100).Parse(formRequest(values))
	if err != nil || secret == nil {
		t.Fatalf("Parse: %+v, %v", secret, err)
	}
	if secret.Type != wicket.ParsedSecretTypesJwtBearer || secret.Id != "client-from-sub" || secret.Credential != assertion {
		t.Fatalf("unexpected secret: %+v", secret)
	}
}

func TestParserFallsBackToTheFormClientId(t *testing.T) {
	key := keyFor(t, "ES256", "k1")
	cases := map[string]string{
		"malformed":         "not-an-assertion",
		"control character": key.sign(t, "ES256", map[string]any{"sub": "cli\nent"}),
		"delete character":  key.sign(t, "ES256", map[string]any{"sub": "cli\x7fent"}),
		"too long":          key.sign(t, "ES256", map[string]any{"sub": strings.Repeat("a", 101)}),
		"not a string":      key.sign(t, "ES256", map[string]any{"sub": 7}),
		"missing":           key.sign(t, "ES256", map[string]any{"iss": "client"}),
	}
	for name, assertion := range cases {
		values := assertionValues(assertion)
		values.Set("client_id", "client-from-form")
		secret, err := NewParser(Options{}, 100).Parse(formRequest(values))
		if err != nil || secret == nil || secret.Id != "client-from-form" || secret.Credential != assertion {
			t.Errorf("%s: got %+v, %v", name, secret, err)
		}
	}

	values := assertionValues("not-an-assertion")
	values.Set("client_id", "cli\tent")
	secret, _ := NewParser(Options{}, 100).Parse(formRequest(values))
	if secret == nil || secret.Id != "" {
		t.Fatalf("unusable form client_id kept: %+v", secret)
	}
}

func TestParserDropsAnOversizedAssertion(t *testing.T) {
	values := assertionValues(strings.Repeat("a", 65))
	values.Set("client_id", "client")
	secret, err := NewParser(Options{MaxAssertionBytes: 64}, 100).Parse(formRequest(values))
	if err != nil || secret == nil || secret.Credential != "" || secret.Type != wicket.ParsedSecretTypesJwtBearer {
		t.Fatalf("got %+v, %v", secret, err)
	}
}

func TestParserTreatsEveryIdentityAsTooLongWithoutALimit(t *testing.T) {
	key := keyFor(t, "ES256", "k1")
	values := assertionValues(key.sign(t, "ES256", map[string]any{"sub": "client"}))
	values.Set("client_id", "client")
	for _, limit := range []int{0, -1} {
		secret, err := NewParser(Options{}, limit).Parse(formRequest(values))
		if err != nil || secret == nil || secret.Id != "" {
			t.Fatalf("limit %d: got %+v, %v", limit, secret, err)
		}
	}
}

func TestParserNamesItsMethodAndAlgorithms(t *testing.T) {
	parser := NewParser(Options{SigningAlgorithms: []string{"PS256", "ES256"}}, 100)
	if parser.AuthenticationMethod() != "private_key_jwt" {
		t.Fatalf("method %q", parser.AuthenticationMethod())
	}
	parser.SigningAlgorithms()[0] = "none"
	if got := parser.SigningAlgorithms(); !slices.Equal(got, []string{"PS256", "ES256"}) {
		t.Fatalf("algorithms %v", got)
	}
	if got := NewParser(Options{}, 100).SigningAlgorithms(); !slices.Equal(got, SupportedSigningAlgorithms()) {
		t.Fatalf("default algorithms %v", got)
	}
}
