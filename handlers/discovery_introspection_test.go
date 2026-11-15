// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/tokens"
)

func TestSettleIntrospectionSigningAdvertisement(t *testing.T) {
	t.Parallel()
	key := wicket.DiscoveryIntrospectionSigningAlgValuesSupported
	const base = "https://as.example/tenant"
	local := base + "/connect/introspect"
	credentials := []*tokens.SigningCredentials{
		{Algorithm: "RS256"}, {Algorithm: "ES256"}, {Algorithm: "RS256"}, {Algorithm: "PS256"},
	}
	cases := map[string]struct {
		document map[string]any
		baseUrl  string
		keys     services.KeyMaterialService
		want     any
		warns    bool
	}{
		"declared and advertised": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: local},
			keys:     &fakeSigningKeys{all: credentials},
			want:     []string{"RS256", "ES256", "PS256"},
		},
		"base url with trailing slash": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: local},
			baseUrl:  base + "/",
			keys:     &fakeSigningKeys{all: credentials},
			want:     []string{"RS256", "ES256", "PS256"},
		},
		"route compares without case": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: "HTTPS://AS.EXAMPLE/tenant/Connect/Introspect"},
			keys:     &fakeSigningKeys{all: credentials[:1]},
			want:     []string{"RS256"},
		},
		"not declared": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: local},
		},
		"endpoint not advertised": {
			document: map[string]any{},
			keys:     &fakeSigningKeys{all: credentials},
		},
		"external endpoint": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: "https://other.example/tenant/connect/introspect"},
			keys:     &fakeSigningKeys{all: credentials},
		},
		"other local route": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: base + "/connect/mtls/introspect"},
			keys:     &fakeSigningKeys{all: credentials},
		},
		"endpoint not a string": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: true},
			keys:     &fakeSigningKeys{all: credentials},
		},
		"no credentials": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: local},
			keys:     &fakeSigningKeys{},
		},
		"credentials without algorithms": {
			document: map[string]any{wicket.DiscoveryIntrospectionEndpoint: local},
			keys:     &fakeSigningKeys{all: []*tokens.SigningCredentials{nil, {}}},
		},
		"custom entry while not declared": {
			document: map[string]any{key: []string{"HS256"}, wicket.DiscoveryIntrospectionEndpoint: local},
			warns:    true,
		},
		"custom entry while declared": {
			document: map[string]any{key: []string{"HS256"}, wicket.DiscoveryIntrospectionEndpoint: local},
			keys:     &fakeSigningKeys{all: credentials[1:2]},
			want:     []string{"ES256"},
			warns:    true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			baseUrl := tc.baseUrl
			if baseUrl == "" {
				baseUrl = base
			}
			err := settleIntrospectionSigningAdvertisement(context.Background(), tc.document, baseUrl, tc.keys, slog.New(slog.NewTextHandler(&logs, nil)))
			if err != nil {
				t.Fatalf("settle: %v", err)
			}
			got, present := tc.document[key]
			if tc.want == nil {
				if present {
					t.Fatalf("advertised %v", got)
				}
			} else if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("advertised %v, want %v", got, tc.want)
			}
			if warned := strings.Contains(logs.String(), key); warned != tc.warns {
				t.Fatalf("warned = %v, logs %q", warned, logs.String())
			}
		})
	}
}

func TestSettleIntrospectionSigningAdvertisementFailsWithTheKeyStore(t *testing.T) {
	t.Parallel()
	failure := errors.New("key store down")
	document := map[string]any{wicket.DiscoveryIntrospectionEndpoint: "https://as.example/connect/introspect"}
	err := settleIntrospectionSigningAdvertisement(context.Background(), document, "https://as.example", &fakeSigningKeys{allErr: failure}, nil)
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want %v", err, failure)
	}
	if _, ok := document[wicket.DiscoveryIntrospectionSigningAlgValuesSupported]; ok {
		t.Fatalf("advertised despite the error")
	}
}

func TestServeSignedIntrospectionRecordsTheKeys(t *testing.T) {
	t.Parallel()
	handler := &DiscoveryHandler{}
	keys := &fakeSigningKeys{}
	handler.ServeSignedIntrospection(keys)
	if handler.introspectionSigningKeys != keys {
		t.Fatalf("keys not recorded")
	}
}

func TestDiscoveryRequestFailsWhenSigningCredentialsCannotBeListed(t *testing.T) {
	t.Parallel()
	failure := errors.New("key store down")
	newHandler := func() *DiscoveryHandler {
		handler := NewDiscoveryHandler(
			&fakeDiscoveryResponseGenerator{document: map[string]any{
				wicket.DiscoveryIntrospectionEndpoint: "https://wicket.test/" + wicket.ProtocolRoutePathsIntrospection,
			}},
			&fakeServerUrls{base: "https://wicket.test"},
			&fakeIssuerNameService{issuer: "https://wicket.test"},
			config_options.NewWicketOptions(),
			[]string{"/" + wicket.ProtocolRoutePathsIntrospection},
			nil, nil,
			quietLogger(),
		)
		handler.ServeSignedIntrospection(&fakeSigningKeys{allErr: failure})
		return handler
	}
	for name, tc := range map[string]struct {
		process func(http.ResponseWriter, *http.Request) error
		path    string
	}{
		"openid configuration":          {process: newHandler().Process, path: wicket.ProtocolRoutePathsDiscoveryConfiguration},
		"authorization server metadata": {process: NewAuthorizationServerMetadataHandler(newHandler()).Process, path: wicket.ProtocolRoutePathsAuthorizationServerMetadata},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			err := tc.process(recorder, httptest.NewRequest(http.MethodGet, "https://wicket.test"+tc.path, nil))
			if !errors.Is(err, failure) {
				t.Fatalf("error = %v, want %v", err, failure)
			}
			if recorder.Body.Len() != 0 {
				t.Fatalf("body written: %q", recorder.Body.String())
			}
		})
	}
}
