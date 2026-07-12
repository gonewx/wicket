// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"net/url"
	"testing"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/storage"
)

// recordingConsentStore captures the key and message handed to Write so tests
// can assert the answer lands under the key the authorize callback expects.
type recordingConsentStore struct {
	key     string
	message *messages.Message[*messages.ConsentResponse]
	writes  int
}

func (s *recordingConsentStore) Write(id string, message *messages.Message[*messages.ConsentResponse]) error {
	s.key = id
	s.message = message
	s.writes++
	return nil
}

func (s *recordingConsentStore) Read(string) (*messages.Message[*messages.ConsentResponse], error) {
	return nil, nil
}

func (s *recordingConsentStore) Delete(string) error { return nil }

// subjectOnlySession is a minimal UserSession fake whose only meaningful
// behavior is returning a fixed authenticated principal from GetUser.
type subjectOnlySession struct{ user *claims.ClaimsPrincipal }

func (s *subjectOnlySession) EnsureSessionIdCookie() error { return nil }
func (s *subjectOnlySession) RemoveSessionIdCookie() error { return nil }
func (s *subjectOnlySession) CreateSessionId(*claims.ClaimsPrincipal, *auth.Properties) (string, error) {
	return "", nil
}
func (s *subjectOnlySession) GetSessionId() string               { return "" }
func (s *subjectOnlySession) GetClientList() ([]string, error)   { return nil, nil }
func (s *subjectOnlySession) GetUser() *claims.ClaimsPrincipal   { return s.user }
func (s *subjectOnlySession) AddClientId(string) error           { return nil }
func (s *subjectOnlySession) Item(string) (any, bool)            { return nil, false }
func (s *subjectOnlySession) SetItem(string, any)                {}

func consentRequestWithParameters(parameters url.Values) *messages.AuthorizationRequest {
	return &messages.AuthorizationRequest{Parameters: parameters}
}

// TestInteractionServiceGrantConsentStoresAnswerUnderDerivedKey verifies the
// answer is written under the subject+parameters key and stamped with the
// injected clock, which is what the authorize callback relies on to pick the
// answer back up.
func TestInteractionServiceGrantConsentStoresAnswerUnderDerivedKey(t *testing.T) {
	t.Parallel()

	store := &recordingConsentStore{}
	clock := newSessionStateClock()
	svc := &InteractionService{consent: NewConsentService(), consentStore: store, clock: clock}

	parameters := url.Values{"client_id": {"client"}, "scope": {"openid profile"}}
	response := &messages.ConsentResponse{ScopesValuesConsented: []string{"openid", "profile"}}

	if err := svc.GrantConsent(consentRequestWithParameters(parameters), response, "alice"); err != nil {
		t.Fatalf("GrantConsent: %v", err)
	}
	if store.writes != 1 {
		t.Fatalf("writes = %d, want 1", store.writes)
	}
	if want := storage.ConsentMessageKey("alice", parameters); store.key != want {
		t.Fatalf("stored key = %q, want %q", store.key, want)
	}
	if store.message == nil || store.message.Data != response {
		t.Fatalf("stored message does not carry the consent response")
	}
	if want := clock.Now().Unix(); store.message.Created != want {
		t.Fatalf("message.Created = %d, want %d", store.message.Created, want)
	}
}

// TestInteractionServiceGrantConsentFallsBackToSessionSubject verifies that an
// empty subject argument resolves the subject from the current user session,
// so the key still matches what the callback derives from its own session.
func TestInteractionServiceGrantConsentFallsBackToSessionSubject(t *testing.T) {
	t.Parallel()

	store := &recordingConsentStore{}
	svc := &InteractionService{
		consent:      NewConsentService(),
		consentStore: store,
		clock:        newSessionStateClock(),
		user:         &subjectOnlySession{user: principalWithSubject("bob")},
	}

	parameters := url.Values{"client_id": {"client"}}
	if err := svc.GrantConsent(consentRequestWithParameters(parameters), &messages.ConsentResponse{}, ""); err != nil {
		t.Fatalf("GrantConsent: %v", err)
	}
	if want := storage.ConsentMessageKey("bob", parameters); store.key != want {
		t.Fatalf("stored key = %q, want %q", store.key, want)
	}
}

// TestInteractionServiceGrantConsentWithoutStoreDoesNotFail verifies the
// degraded wiring (no consent store or no request) stays a silent no-op
// instead of failing the interaction.
func TestInteractionServiceGrantConsentWithoutStoreDoesNotFail(t *testing.T) {
	t.Parallel()

	tests := map[string]*InteractionService{
		"nil store":   {consent: NewConsentService()},
		"nil request": {consent: NewConsentService(), consentStore: &recordingConsentStore{}},
	}
	for name, svc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var request *messages.AuthorizationRequest
			if svc.consentStore == nil {
				request = consentRequestWithParameters(url.Values{})
			}
			if err := svc.GrantConsent(request, &messages.ConsentResponse{}, "alice"); err != nil {
				t.Fatalf("GrantConsent: %v", err)
			}
		})
	}
}

// TestInteractionServiceGetAuthorizationContextWithoutParser verifies the
// unwired-parser form degrades to an empty context instead of panicking.
func TestInteractionServiceGetAuthorizationContextWithoutParser(t *testing.T) {
	t.Parallel()

	svc := &InteractionService{consent: NewConsentService()}
	request, err := svc.GetAuthorizationContext("/authorize/callback?client_id=client")
	if err != nil {
		t.Fatalf("GetAuthorizationContext: %v", err)
	}
	if request != nil {
		t.Fatalf("request = %+v, want nil without a parser", request)
	}
}
