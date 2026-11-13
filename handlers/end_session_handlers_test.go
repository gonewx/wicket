// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
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
		backChannel := &recordingBackchannelLogout{}
		handler := NewEndSessionCallbackHandler(
			&fakeEndSessionRequestValidator{callbackResult: failed},
			backChannel,
			freshLogoutContextStore(),
			handlerClock{},
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
		if len(backChannel.sent) != 0 {
			t.Fatalf("back-channel logout was triggered on a failed callback")
		}
	})

	t.Run("POST returns 405", func(t *testing.T) {
		t.Parallel()
		handler := NewEndSessionCallbackHandler(
			&fakeEndSessionRequestValidator{},
			&recordingBackchannelLogout{},
			freshLogoutContextStore(),
			handlerClock{},
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

type recordingBackchannelLogout struct {
	sent []*contexts.LogoutNotificationContext
	err  error
}

func (b *recordingBackchannelLogout) SendLogoutNotificationsAsync(notification *contexts.LogoutNotificationContext) error {
	b.sent = append(b.sent, notification)
	return b.err
}

type fakeLogoutContextStore struct {
	message *messages.Message[*contexts.LogoutNotificationContext]
	err     error
	read    []string
}

func (s *fakeLogoutContextStore) Write(ctx context.Context, message *messages.Message[*contexts.LogoutNotificationContext]) (string, error) {
	s.message = message
	return "handle", nil
}

func (s *fakeLogoutContextStore) Read(ctx context.Context, handle string) (*messages.Message[*contexts.LogoutNotificationContext], error) {
	s.read = append(s.read, handle)
	return s.message, s.err
}

// optionsScope is a resolution scope that serves only the options, which the
// rendered callback page resolves from the request scope.
type optionsScope struct{ options *config_options.WicketOptions }

func (s optionsScope) GetService(t reflect.Type) any {
	if t == reflect.TypeFor[*config_options.WicketOptions]() {
		return s.options
	}
	return nil
}
func (s optionsScope) IsService(t reflect.Type) bool {
	return t == reflect.TypeFor[*config_options.WicketOptions]()
}
func (optionsScope) IsKeyedService(reflect.Type, any) bool    { return false }
func (optionsScope) GetKeyedService(reflect.Type, any) any    { return nil }
func (optionsScope) GetKeyedServices(reflect.Type, any) []any { return nil }
func (optionsScope) CreateScope() godi.Scope                  { return nil }
func (optionsScope) Close() error                             { return nil }

// handlerClock is the injected clock of the callback handler tests; it stands
// a fixed distance away from wall-clock time so the staleness check is shown
// to read the injected clock rather than the system time.
type handlerClock struct{}

var handlerNow = time.Now().Add(-48 * time.Hour)

func (handlerClock) Now() time.Time { return handlerNow }

func freshLogoutContextStore() *fakeLogoutContextStore {
	return &fakeLogoutContextStore{message: messages.NewMessageWithCreated(&contexts.LogoutNotificationContext{
		SubjectId: "bob",
		SessionId: "session-1",
		ClientIds: []string{"rp"},
	}, handlerNow.Unix())}
}

func TestEndSessionCallbackHandlerBackChannelLogout(t *testing.T) {
	t.Parallel()

	process := func(t *testing.T, store *fakeLogoutContextStore, backChannel *recordingBackchannelLogout) *httptest.ResponseRecorder {
		t.Helper()
		options := config_options.NewWicketOptions()
		handler := NewEndSessionCallbackHandler(
			&fakeEndSessionRequestValidator{callbackResult: validators_models.NewEndSessionCallbackValidationResult()},
			backChannel,
			store,
			handlerClock{},
			options,
			quietLogger(),
		)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://wicket.test/connect/endsession/callback?endSessionId=the-handle", nil)
		request = request.WithContext(hosting.ContextWithScope(request.Context(), optionsScope{options: options}))
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", recorder.Code)
		}
		return recorder
	}

	t.Run("valid callback delivers the logout context of its handle", func(t *testing.T) {
		t.Parallel()
		store := freshLogoutContextStore()
		backChannel := &recordingBackchannelLogout{}

		process(t, store, backChannel)

		if len(store.read) != 1 || store.read[0] != "the-handle" {
			t.Fatalf("store reads = %v, want one read of the callback handle", store.read)
		}
		if len(backChannel.sent) != 1 || backChannel.sent[0] != store.message.Data {
			t.Fatalf("back-channel logout sent %d contexts, want the stored one", len(backChannel.sent))
		}
	})

	t.Run("store read failure still renders the page", func(t *testing.T) {
		t.Parallel()
		store := freshLogoutContextStore()
		store.err = errors.New("store unavailable")
		backChannel := &recordingBackchannelLogout{}

		process(t, store, backChannel)

		if len(backChannel.sent) != 0 {
			t.Fatal("back-channel logout was triggered without a logout context")
		}
	})

	t.Run("missing logout context still renders the page", func(t *testing.T) {
		t.Parallel()
		store := &fakeLogoutContextStore{}
		backChannel := &recordingBackchannelLogout{}

		process(t, store, backChannel)

		if len(backChannel.sent) != 0 {
			t.Fatal("back-channel logout was triggered without a logout context")
		}
	})

	t.Run("delivery error still renders the page", func(t *testing.T) {
		t.Parallel()
		backChannel := &recordingBackchannelLogout{err: errors.New("delivery failed")}

		process(t, freshLogoutContextStore(), backChannel)

		if len(backChannel.sent) != 1 {
			t.Fatalf("back-channel logout sent %d contexts, want 1", len(backChannel.sent))
		}
	})

	t.Run("stale logout context is not delivered", func(t *testing.T) {
		t.Parallel()
		store := freshLogoutContextStore()
		store.message.Created = handlerNow.Add(-301 * time.Second).Unix()
		backChannel := &recordingBackchannelLogout{}

		process(t, store, backChannel)

		if len(backChannel.sent) != 0 {
			t.Fatal("back-channel logout was triggered for a stale logout context")
		}
	})

	t.Run("recent logout context within the replay window is delivered", func(t *testing.T) {
		t.Parallel()
		store := freshLogoutContextStore()
		store.message.Created = handlerNow.Add(-290 * time.Second).Unix()
		backChannel := &recordingBackchannelLogout{}

		process(t, store, backChannel)

		if len(backChannel.sent) != 1 {
			t.Fatalf("back-channel logout sent %d contexts, want 1", len(backChannel.sent))
		}
	})
}
