// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	core_models "github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/tokens"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type fakeSigningKeys struct {
	credential *tokens.SigningCredentials
	all        []*tokens.SigningCredentials
	err        error
	allErr     error
	allowed    [][]string
}

func (k *fakeSigningKeys) GetSigningCredentials(_ context.Context, allowed []string) (*tokens.SigningCredentials, error) {
	k.allowed = append(k.allowed, allowed)
	return k.credential, k.err
}

func (k *fakeSigningKeys) GetAllSigningCredentials(context.Context) ([]*tokens.SigningCredentials, error) {
	return k.all, k.allErr
}

func (k *fakeSigningKeys) GetValidationKeys(context.Context) ([]*core_models.SecurityKeyInfo, error) {
	return nil, nil
}

type fixedIssuer string

func (i fixedIssuer) GetCurrent() string { return string(i) }

func TestAcceptsIntrospectionJwt(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		accept []string
		want   bool
	}{
		"no header":                 {},
		"empty header":              {accept: []string{""}},
		"json":                      {accept: []string{"application/json"}},
		"exact":                     {accept: []string{"application/token-introspection+jwt"}, want: true},
		"mixed case":                {accept: []string{"Application/Token-Introspection+JWT"}, want: true},
		"among others with quality": {accept: []string{"application/json, Application/Token-Introspection+JWT;q=0.5"}, want: true},
		"extra spaces":              {accept: []string{"  application/json ,   application/token-introspection+jwt  ;  q=1  "}, want: true},
		"quality zero":              {accept: []string{"application/token-introspection+jwt;q=0"}},
		"quality zero decimals":     {accept: []string{"application/token-introspection+jwt; q=0.000"}},
		"parameter name case":       {accept: []string{"application/token-introspection+jwt;Q=0"}},
		"upper case quality one":    {accept: []string{"application/token-introspection+jwt;Q=1"}, want: true},
		"other parameter":           {accept: []string{"application/token-introspection+jwt;charset=utf-8"}, want: true},
		"unreadable quality":        {accept: []string{"application/token-introspection+jwt;q=high"}},
		"any":                       {accept: []string{"*/*"}},
		"application any":           {accept: []string{"application/*"}},
		"plain jwt":                 {accept: []string{"application/jwt"}},
		"second header":             {accept: []string{"application/json", "application/token-introspection+jwt"}, want: true},
		"prefix only":               {accept: []string{"application/token-introspection+jwtx"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := acceptsIntrospectionJwt(tc.accept); got != tc.want {
				t.Fatalf("acceptsIntrospectionJwt(%q) = %v, want %v", tc.accept, got, tc.want)
			}
		})
	}
}

func newSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func newSignedIntrospectionHandler(keys *fakeSigningKeys, entries map[string]any) *IntrospectionHandler {
	result := validators_models.NewIntrospectionRequestValidationResult()
	result.Api = storage_models.NewApiResource()
	result.Api.Name = "api1"
	handler := NewIntrospectionHandler(
		&fakeApiSecretValidator{result: validators_models.NewApiSecretValidationResult()},
		&fakeIntrospectionRequestValidator{result: result},
		&fakeIntrospectionResponseGenerator{entries: entries},
		quietLogger(),
	)
	if keys != nil {
		handler.ServeSignedResponses(keys, fixedIssuer("https://as.example"), fixedClock{now: time.Unix(1763200000, 0)})
	}
	return handler
}

func jwtIntrospectionRequest(accept string) *http.Request {
	request := newIntrospectionForm("token=known")
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	return request
}

func TestIntrospectionHandlerSignsTheResponse(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	entries := map[string]any{"active": true, "client_id": "client1", "scope": "api1", "cnf": map[string]any{"jkt": "x"}}

	for name, tc := range map[string]struct {
		kid     string
		entries map[string]any
	}{
		"active with kid":      {kid: "key-1", entries: entries},
		"active without kid":   {entries: entries},
		"inactive":             {kid: "key-1", entries: map[string]any{"active": false}},
		"nil generator result": {kid: "key-1"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keys := &fakeSigningKeys{credential: &tokens.SigningCredentials{Key: key, Algorithm: "ES256", Kid: tc.kid}}
			handler := newSignedIntrospectionHandler(keys, tc.entries)
			recorder := httptest.NewRecorder()
			if err := handler.Process(recorder, jwtIntrospectionRequest(wicket.MediaTypesTokenIntrospectionJwt)); err != nil {
				t.Fatalf("Process: %v", err)
			}
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d", recorder.Code)
			}
			if got := recorder.Header().Get("Content-Type"); got != wicket.MediaTypesTokenIntrospectionJwt {
				t.Fatalf("content type = %q", got)
			}
			if got := recorder.Header().Values("Cache-Control"); !slices.Equal(got, []string{"no-store", "no-cache", "max-age=0"}) {
				t.Fatalf("cache control = %q", got)
			}
			if got := recorder.Header().Get("Pragma"); got != "no-cache" {
				t.Fatalf("pragma = %q", got)
			}
			if !reflect.DeepEqual(keys.allowed, [][]string{nil}) {
				t.Fatalf("credential selection restricted to %v", keys.allowed)
			}
			body := recorder.Body.String()
			if strings.HasSuffix(body, "\n") || strings.Count(body, ".") != 2 {
				t.Fatalf("body is not a compact JWT: %q", body)
			}

			payload, err := jws.Verify([]byte(body), jws.WithKey(jwa.ES256(), key.Public()))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			message, err := jws.Parse([]byte(body))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			headers := message.Signatures()[0].ProtectedHeaders()
			if typ, _ := headers.Type(); typ != wicket.JwtTypesTokenIntrospection {
				t.Fatalf("typ = %q", typ)
			}
			if alg, _ := headers.Algorithm(); alg.String() != "ES256" {
				t.Fatalf("alg = %v", alg)
			}
			kid, hasKid := headers.KeyID()
			if hasKid != (tc.kid != "") || kid != tc.kid {
				t.Fatalf("kid = %q (present %v), want %q", kid, hasKid, tc.kid)
			}

			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if got := slices.Sorted(maps.Keys(claims)); !slices.Equal(got, []string{"aud", "iat", "iss", "token_introspection"}) {
				t.Fatalf("payload keys = %v", got)
			}
			if claims["iss"] != "https://as.example" || claims["aud"] != "api1" || claims["iat"] != float64(1763200000) {
				t.Fatalf("payload = %v", claims)
			}
			want := map[string]any{}
			if tc.entries != nil {
				raw, _ := json.Marshal(tc.entries)
				_ = json.Unmarshal(raw, &want)
			}
			if !reflect.DeepEqual(claims[wicket.ClaimTypesTokenIntrospection], want) {
				t.Fatalf("token_introspection = %v, want %v", claims[wicket.ClaimTypesTokenIntrospection], want)
			}
		})
	}
}

func TestIntrospectionHandlerAnswersJsonUnlessJwtIsRequested(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	entries := map[string]any{"active": true, "scope": "api1"}
	for name, tc := range map[string]struct {
		signing bool
		accept  string
	}{
		"no accept":                 {signing: true},
		"json accept":               {signing: true, accept: "application/json"},
		"any":                       {signing: true, accept: "*/*"},
		"quality zero":              {signing: true, accept: "application/token-introspection+jwt;q=0"},
		"no signing material":       {accept: wicket.MediaTypesTokenIntrospectionJwt},
		"no signing material mixed": {accept: "application/json, application/token-introspection+jwt"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var keys *fakeSigningKeys
			if tc.signing {
				keys = &fakeSigningKeys{credential: &tokens.SigningCredentials{Key: key, Algorithm: "ES256"}}
			}
			recorder := httptest.NewRecorder()
			if err := newSignedIntrospectionHandler(keys, entries).Process(recorder, jwtIntrospectionRequest(tc.accept)); err != nil {
				t.Fatalf("Process: %v", err)
			}
			baseline := httptest.NewRecorder()
			if err := newSignedIntrospectionHandler(nil, entries).Process(baseline, jwtIntrospectionRequest("")); err != nil {
				t.Fatalf("Process: %v", err)
			}
			if recorder.Code != baseline.Code || !reflect.DeepEqual(recorder.Header(), baseline.Header()) || recorder.Body.String() != baseline.Body.String() {
				t.Fatalf("response %d %v %q differs from JSON %d %v %q", recorder.Code, recorder.Header(), recorder.Body.String(), baseline.Code, baseline.Header(), baseline.Body.String())
			}
			if keys != nil && len(keys.allowed) != 0 {
				t.Fatalf("a signing credential was selected for a JSON response")
			}
		})
	}
}

func TestIntrospectionHandlerFailsWithoutSigningCredential(t *testing.T) {
	t.Parallel()
	failure := errors.New("key store down")
	for name, tc := range map[string]struct {
		keys    *fakeSigningKeys
		wantErr error
	}{
		"selection error":     {keys: &fakeSigningKeys{err: failure}, wantErr: failure},
		"nil credential":      {keys: &fakeSigningKeys{}},
		"credential sans key": {keys: &fakeSigningKeys{credential: &tokens.SigningCredentials{Algorithm: "ES256"}}},
		"unknown algorithm":   {keys: &fakeSigningKeys{credential: &tokens.SigningCredentials{Key: newSigningKey(t), Algorithm: "none-such"}}},
		"mismatched key":      {keys: &fakeSigningKeys{credential: &tokens.SigningCredentials{Key: newSigningKey(t), Algorithm: "RS256"}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			err := newSignedIntrospectionHandler(tc.keys, map[string]any{"active": true}).Process(recorder, jwtIntrospectionRequest(wicket.MediaTypesTokenIntrospectionJwt))
			if err == nil {
				t.Fatalf("Process succeeded: %d %q", recorder.Code, recorder.Body.String())
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error %v does not wrap %v", err, tc.wantErr)
			}
			if recorder.Body.Len() != 0 || len(recorder.Header()) != 0 {
				t.Fatalf("response written: %v %q", recorder.Header(), recorder.Body.String())
			}
		})
	}
}

func TestIntrospectionHandlerErrorPathsIgnoreAccept(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	failedApi := validators_models.NewApiSecretValidationResult()
	failedApi.Error = wicket.TokenErrorsInvalidRequest
	invalid := validators_models.NewIntrospectionRequestValidationResult()
	invalid.Error = wicket.TokenErrorsInvalidRequest

	for name, tc := range map[string]struct {
		request       func() *http.Request
		apiResult     *validators_models.ApiSecretValidationResult
		requestResult *validators_models.IntrospectionRequestValidationResult
	}{
		"GET": {request: func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/introspect", nil)
		}},
		"JSON body": {request: func() *http.Request {
			request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/introspect", strings.NewReader("{}"))
			request.Header.Set("Content-Type", "application/json")
			return request
		}},
		"failed authentication": {request: func() *http.Request { return newIntrospectionForm("token=x") }, apiResult: failedApi},
		"invalid request": {
			request:       func() *http.Request { return newIntrospectionForm("") },
			apiResult:     validators_models.NewApiSecretValidationResult(),
			requestResult: invalid,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			run := func(signing bool, accept string) *httptest.ResponseRecorder {
				handler := NewIntrospectionHandler(
					&fakeApiSecretValidator{result: tc.apiResult},
					&fakeIntrospectionRequestValidator{result: tc.requestResult},
					&fakeIntrospectionResponseGenerator{entries: map[string]any{"active": true}},
					quietLogger(),
				)
				if signing {
					handler.ServeSignedResponses(&fakeSigningKeys{credential: &tokens.SigningCredentials{Key: key, Algorithm: "ES256"}}, fixedIssuer("https://as.example"), fixedClock{now: time.Unix(0, 0)})
				}
				request := tc.request()
				if accept != "" {
					request.Header.Set("Accept", accept)
				}
				recorder := httptest.NewRecorder()
				if err := handler.Process(recorder, request); err != nil {
					t.Fatalf("Process: %v", err)
				}
				return recorder
			}
			got := run(true, wicket.MediaTypesTokenIntrospectionJwt)
			want := run(false, "")
			if got.Code != want.Code || !reflect.DeepEqual(got.Header(), want.Header()) || got.Body.String() != want.Body.String() {
				t.Fatalf("response %d %v %q differs from %d %v %q", got.Code, got.Header(), got.Body.String(), want.Code, want.Header(), want.Body.String())
			}
		})
	}
}

func TestSwitchedOffIntrospectionIgnoresAccept(t *testing.T) {
	t.Parallel()
	options := config_options.NewWicketOptions()
	options.Endpoints.EnableIntrospectionEndpoint = false
	handler := NewIntrospectionHandlerWithOptions(
		&fakeApiSecretValidator{result: validators_models.NewApiSecretValidationResult()},
		&fakeIntrospectionRequestValidator{result: validators_models.NewIntrospectionRequestValidationResult()},
		&fakeIntrospectionResponseGenerator{entries: map[string]any{"active": true}},
		options,
		quietLogger(),
	)
	handler.ServeSignedResponses(&fakeSigningKeys{credential: &tokens.SigningCredentials{Key: newSigningKey(t), Algorithm: "ES256"}}, fixedIssuer("https://as.example"), fixedClock{now: time.Unix(0, 0)})
	recorder := httptest.NewRecorder()
	if err := handler.Process(recorder, jwtIntrospectionRequest(wicket.MediaTypesTokenIntrospectionJwt)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if recorder.Code != http.StatusNotFound || recorder.Header().Get("Content-Type") == wicket.MediaTypesTokenIntrospectionJwt {
		t.Fatalf("status = %d, headers %v", recorder.Code, recorder.Header())
	}
}

func TestServeSignedResponsesNeedsEveryDependency(t *testing.T) {
	t.Parallel()
	handler := newSignedIntrospectionHandler(nil, nil)
	handler.ServeSignedResponses(&fakeSigningKeys{}, nil, fixedClock{now: time.Unix(0, 0)})
	if handler.signing != nil {
		t.Fatalf("signing enabled without an issuer")
	}
}
