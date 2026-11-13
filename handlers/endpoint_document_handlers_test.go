// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
)

type fakeDiscoveryResponseGenerator struct {
	document map[string]any
	keys     []*models.JsonWebKey
	err      error
}

func (g *fakeDiscoveryResponseGenerator) CreateDiscoveryDocument(ctx context.Context, baseUrl string, issuerUri string) (map[string]any, error) {
	if g.err != nil {
		return nil, g.err
	}
	document := map[string]any{"issuer": issuerUri, "base": baseUrl}
	for k, v := range g.document {
		document[k] = v
	}
	return document, nil
}

func (g *fakeDiscoveryResponseGenerator) CreateJwkDocument(ctx context.Context) ([]*models.JsonWebKey, error) {
	return g.keys, g.err
}

type fakeServerUrls struct{ base string }

func (u *fakeServerUrls) Origin() string                         { return u.base }
func (u *fakeServerUrls) BasePath() string                       { return "" }
func (u *fakeServerUrls) BaseUrl() string                        { return u.base }
func (u *fakeServerUrls) GetWicketRelativeUrl(rel string) string { return u.base + rel }

type fakeIssuerNameService struct{ issuer string }

func (s *fakeIssuerNameService) GetCurrent() string { return s.issuer }

func quietLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestDiscoveryHandlerDispatch(t *testing.T) {
	t.Parallel()

	options := config_options.NewWicketOptions()
	handler := NewDiscoveryHandler(
		&fakeDiscoveryResponseGenerator{},
		&fakeServerUrls{base: "https://wicket.test"},
		&fakeIssuerNameService{issuer: "https://wicket.test"},
		options,
		nil, nil, nil,
		quietLogger(),
	)

	t.Run("non-GET returns 405", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "https://wicket.test/.well-known/openid-configuration", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", recorder.Code)
		}
	})

	t.Run("GET returns the issuer document", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/.well-known/openid-configuration", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", recorder.Code)
		}
		var document map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
			t.Fatalf("unmarshal document: %v", err)
		}
		if document["issuer"] != "https://wicket.test" {
			t.Fatalf("issuer = %v, want the configured issuer", document["issuer"])
		}
	})

	t.Run("disabled endpoint returns 404", func(t *testing.T) {
		disabled := config_options.NewWicketOptions()
		disabled.Endpoints.EnableDiscoveryEndpoint = false
		handler := NewDiscoveryHandler(
			&fakeDiscoveryResponseGenerator{},
			&fakeServerUrls{base: "https://wicket.test"},
			&fakeIssuerNameService{issuer: "https://wicket.test"},
			disabled,
			nil, nil, nil,
			quietLogger(),
		)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/.well-known/openid-configuration", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", recorder.Code)
		}
	})
}

func TestDiscoveryKeyHandlerDispatch(t *testing.T) {
	t.Parallel()

	handler := NewDiscoveryKeyHandler(&fakeDiscoveryResponseGenerator{}, config_options.NewWicketOptions(), quietLogger())

	t.Run("GET returns a keys document", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/.well-known/openid-configuration/jwks", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", recorder.Code)
		}
		var document map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
			t.Fatalf("unmarshal document: %v", err)
		}
		if _, ok := document["keys"]; !ok {
			t.Fatal("document missing keys member")
		}
	})

	t.Run("hidden key set returns 404", func(t *testing.T) {
		options := config_options.NewWicketOptions()
		options.Discovery.ShowKeySet = false
		handler := NewDiscoveryKeyHandler(&fakeDiscoveryResponseGenerator{}, options, quietLogger())
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/.well-known/openid-configuration/jwks", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", recorder.Code)
		}
	})
}

func TestCheckSessionHandlerMethodAndSwitchGuards(t *testing.T) {
	t.Parallel()

	t.Run("non-GET returns 405", func(t *testing.T) {
		handler := NewCheckSessionHandler(config_options.NewWicketOptions(), quietLogger())
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/checksession", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", recorder.Code)
		}
	})

	t.Run("disabled endpoint returns 404", func(t *testing.T) {
		options := config_options.NewWicketOptions()
		options.Endpoints.EnableCheckSessionEndpoint = false
		handler := NewCheckSessionHandler(options, quietLogger())
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/checksession", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", recorder.Code)
		}
	})
}
