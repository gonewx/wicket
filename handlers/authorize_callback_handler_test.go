// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// fakeConsentMessageStore is an in-memory consent store keyed by identifier.
type fakeConsentMessageStore struct {
	entries map[string]*messages.Message[*messages.ConsentResponse]
}

func newFakeConsentMessageStore() *fakeConsentMessageStore {
	return &fakeConsentMessageStore{entries: make(map[string]*messages.Message[*messages.ConsentResponse])}
}

func (s *fakeConsentMessageStore) Write(id string, message *messages.Message[*messages.ConsentResponse]) error {
	s.entries[id] = message
	return nil
}

func (s *fakeConsentMessageStore) Read(id string) (*messages.Message[*messages.ConsentResponse], error) {
	return s.entries[id], nil
}

func (s *fakeConsentMessageStore) Delete(id string) error {
	delete(s.entries, id)
	return nil
}

func callbackSubject(t *testing.T) *claims.ClaimsPrincipal {
	t.Helper()
	subject, err := models.NewLocalUser(models.WithLocalUserSubjectId("some-subject")).CreatePrincipal()
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	return subject
}

func callbackRequest() (*http.Request, url.Values) {
	values := url.Values{
		gois.AuthorizeRequestClientId: {"some-client"},
		gois.AuthorizeRequestScope:    {"openid"},
		gois.AuthorizeRequestNonce:    {"some-nonce"},
	}
	target := "https://wicket.test" + gois.ProtocolRoutePathsAuthorizeCallback + "?" + values.Encode()
	return httptest.NewRequest(http.MethodGet, target, nil), values
}

func newCallbackHandler(
	subject *claims.ClaimsPrincipal,
	interaction *responses_models.InteractionResponse,
	store *fakeConsentMessageStore,
) *AuthorizeCallbackHandler {
	return NewAuthorizeCallbackHandler(
		&fakeAuthorizeRequestValidator{result: validators_models.NewAuthorizeRequestValidationResult(validRequest())},
		&fakeInteractionGenerator{response: interaction},
		&fakeAuthorizeResponseGenerator{response: responses_models.NewAuthorizeResponse()},
		&fakeUserSession{user: subject},
		store,
		nil,
		nil,
	)
}

func grantedConsentMessage() *messages.Message[*messages.ConsentResponse] {
	consent := messages.NewConsentResponse()
	consent.ScopesValuesConsented = []string{"openid"}
	return messages.NewMessage(consent)
}

func TestAuthorizeCallbackHandlerResumeDispatch(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		interaction *responses_models.InteractionResponse
		seed        func(subject *claims.ClaimsPrincipal, values url.Values, store *fakeConsentMessageStore)
		assert      func(t *testing.T, result endpointResult)
	}{
		"valid consent answer resumes to authorize result": {
			interaction: responses_models.NewInteractionResponse(),
			seed: func(subject *claims.ClaimsPrincipal, values url.Values, store *fakeConsentMessageStore) {
				_ = store.Write(consentRequestKey(subject, values), grantedConsentMessage())
			},
			assert: func(t *testing.T, result endpointResult) {
				if _, ok := result.(*results.AuthorizeResult); !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
			},
		},
		"login return without consent resumes to authorize result": {
			interaction: responses_models.NewInteractionResponse(),
			seed:        func(*claims.ClaimsPrincipal, url.Values, *fakeConsentMessageStore) {},
			assert: func(t *testing.T, result endpointResult) {
				if _, ok := result.(*results.AuthorizeResult); !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
			},
		},
		"missing consent answer builds error authorize result": {
			interaction: responses_models.NewInteractionResponse(),
			seed: func(subject *claims.ClaimsPrincipal, values url.Values, store *fakeConsentMessageStore) {
				_ = store.Write(consentRequestKey(subject, values), &messages.Message[*messages.ConsentResponse]{})
			},
			assert: func(t *testing.T, result endpointResult) {
				authorizeResult, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if authorizeResult.Response.Error == nil {
					t.Fatal("response error = nil, want non-nil")
				}
			},
		},
		"no consent message with consent interaction builds consent page result": {
			interaction: &responses_models.InteractionResponse{IsConsent: true},
			seed:        func(*claims.ClaimsPrincipal, url.Values, *fakeConsentMessageStore) {},
			assert: func(t *testing.T, result endpointResult) {
				if _, ok := result.(*results.ConsentPageResult); !ok {
					t.Fatalf("result = %T, want *results.ConsentPageResult", result)
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			subject := callbackSubject(t)
			req, values := callbackRequest()
			store := newFakeConsentMessageStore()
			tt.seed(subject, values, store)

			handler := newCallbackHandler(subject, tt.interaction, store)
			result, err := handler.result(req)
			if err != nil {
				t.Fatalf("result: %v", err)
			}
			tt.assert(t, result)
		})
	}
}

func TestAuthorizeCallbackHandlerConsumesConsentMessage(t *testing.T) {
	t.Parallel()

	subject := callbackSubject(t)
	req, values := callbackRequest()
	store := newFakeConsentMessageStore()
	_ = store.Write(consentRequestKey(subject, values), grantedConsentMessage())

	handler := newCallbackHandler(subject, responses_models.NewInteractionResponse(), store)
	if _, err := handler.result(req); err != nil {
		t.Fatalf("result: %v", err)
	}

	if len(store.entries) != 0 {
		t.Fatalf("consent store entries = %d, want 0 (consumed)", len(store.entries))
	}
}

func TestAuthorizeCallbackHandlerRejectsNonGet(t *testing.T) {
	t.Parallel()

	subject := callbackSubject(t)
	store := newFakeConsentMessageStore()
	handler := newCallbackHandler(subject, responses_models.NewInteractionResponse(), store)

	req := httptest.NewRequest(http.MethodPost, "https://wicket.test"+gois.ProtocolRoutePathsAuthorizeCallback, nil)
	rec := httptest.NewRecorder()
	if err := handler.Process(rec, req); err != nil {
		t.Fatalf("process: %v", err)
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
