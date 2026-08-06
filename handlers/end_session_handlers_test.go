// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type fakeEndSessionRequestValidator struct {
	result         *validators_models.EndSessionValidationResult
	callbackResult *validators_models.EndSessionCallbackValidationResult
}

func (v *fakeEndSessionRequestValidator) Validate(ctx context.Context, values url.Values, subject *claims.ClaimsPrincipal) (*validators_models.EndSessionValidationResult, error) {
	return v.result, nil
}

func (v *fakeEndSessionRequestValidator) ValidateCallback(ctx context.Context, values url.Values) (*validators_models.EndSessionCallbackValidationResult, error) {
	return v.callbackResult, nil
}

func TestEndSessionHandlerGuards(t *testing.T) {
	t.Parallel()

	newHandler := func(options *config_options.WicketOptions) *EndSessionHandler {
		return NewEndSessionHandler(
			&fakeEndSessionRequestValidator{result: validators_models.NewEndSessionValidationResult()},
			&fakeUserSession{},
			options,
			quietLogger(),
		)
	}

	t.Run("DELETE returns 405", func(t *testing.T) {
		t.Parallel()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodDelete, "https://wicket.test/connect/endsession", nil)
		if err := newHandler(config_options.NewWicketOptions()).Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", recorder.Code)
		}
	})

	t.Run("POST without a form content type returns 415", func(t *testing.T) {
		t.Parallel()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/endsession", nil)
		request.Header.Set("Content-Type", "application/json")
		if err := newHandler(config_options.NewWicketOptions()).Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415", recorder.Code)
		}
	})

	t.Run("disabled endpoint returns 404", func(t *testing.T) {
		t.Parallel()
		options := config_options.NewWicketOptions()
		options.Endpoints.EnableEndSessionEndpoint = false
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/endsession", nil)
		if err := newHandler(options).Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", recorder.Code)
		}
	})
}

func TestEndSessionCallbackHandlerGuards(t *testing.T) {
	t.Parallel()

	t.Run("invalid callback returns 400", func(t *testing.T) {
		t.Parallel()
		failed := validators_models.NewEndSessionCallbackValidationResult()
		failed.Error = http.ErrNoCookie
		handler := NewEndSessionCallbackHandler(
			&fakeEndSessionRequestValidator{callbackResult: failed},
			config_options.NewWicketOptions(),
			quietLogger(),
		)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/endsession/callback", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", recorder.Code)
		}
	})

	t.Run("POST returns 405", func(t *testing.T) {
		t.Parallel()
		handler := NewEndSessionCallbackHandler(
			&fakeEndSessionRequestValidator{},
			config_options.NewWicketOptions(),
			quietLogger(),
		)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "https://wicket.test/connect/endsession/callback", nil)
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", recorder.Code)
		}
	})
}
