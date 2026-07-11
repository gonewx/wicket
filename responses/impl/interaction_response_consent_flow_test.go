// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/test/common"
)

func consentGenerator(consent *common.MockConsentService) *AuthorizeInteractionResponseGenerator {
	return buildGenerator(
		fixedClock(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)),
		consent,
		common.NewMockProfileService(),
	)
}

// TestHandleConsentRejectsNilRequest covers the nil-request guard.
func TestHandleConsentRejectsNilRequest(t *testing.T) {
	t.Parallel()

	g := consentGenerator(common.NewMockConsentService())

	resp := g.HandleConsent(nil, messages.NewConsentResponse())

	if !resp.IsError() {
		t.Fatalf("expected an error result for a nil request, got %+v", resp)
	}
}

// TestHandleConsentRejectsLoginClassPrompt covers the prompt guard: consent
// handling accepts only a consent-class prompt, so a login/select_account prompt
// reaching it is an error regardless of whether consent would be required.
func TestHandleConsentRejectsLoginClassPrompt(t *testing.T) {
	t.Parallel()

	for name, prompt := range map[string]string{
		"select_account prompt": gois.PromptModesSelectAccount,
		"login prompt":          gois.PromptModesLogin,
	} {
		prompt := prompt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consent := common.NewMockConsentService()
			consent.RequiresConsentResult = true
			req := consentRequest(t)
			req.PromptModes = []string{prompt}
			g := consentGenerator(consent)

			resp := g.HandleConsent(req, nil)

			if !resp.IsError() {
				t.Fatalf("expected an error result for a %q prompt, got %+v", prompt, resp)
			}
		})
	}
}

// TestHandleConsentShowsPageWhenUnanswered covers the show-consent-page outcome:
// once consent is required but the user has not yet answered, the handler returns
// a consent interaction without an error and without persisting anything.
func TestHandleConsentShowsPageWhenUnanswered(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		requiresConsent bool
		prompt          []string
	}{
		"prompt=consent alone requests the page": {
			requiresConsent: false,
			prompt:          []string{gois.PromptModesConsent},
		},
		"service requirement plus prompt=consent requests the page": {
			requiresConsent: true,
			prompt:          []string{gois.PromptModesConsent},
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consent := common.NewMockConsentService()
			consent.RequiresConsentResult = tc.requiresConsent
			req := consentRequest(t)
			req.PromptModes = tc.prompt
			g := consentGenerator(consent)

			resp := g.HandleConsent(req, nil)

			if resp.IsError() {
				t.Fatalf("did not expect an error, got %v", resp.Error)
			}
			if !resp.IsConsent {
				t.Fatalf("IsConsent = false, want true")
			}
			if req.WasConsentShown {
				t.Fatalf("WasConsentShown = true, want false before the page is answered")
			}
			if consent.ConsentSubject != nil {
				t.Fatalf("consent was persisted before an answer was submitted")
			}
		})
	}
}

// TestHandleConsentAllowsWhenNotRequired covers the pass-through path: when neither
// a consent-class prompt nor the consent service demands a decision, the handler
// returns a plain non-consent, non-error result without showing a page or
// persisting anything. This is the common no-interaction case.
func TestHandleConsentAllowsWhenNotRequired(t *testing.T) {
	t.Parallel()

	consent := common.NewMockConsentService()
	consent.RequiresConsentResult = false
	req := consentRequest(t)
	g := consentGenerator(consent)

	resp := g.HandleConsent(req, nil)

	if resp.IsError() {
		t.Fatalf("did not expect an error, got %v", resp.Error)
	}
	if resp.IsConsent {
		t.Fatalf("IsConsent = true, want false when consent is not required")
	}
	if req.WasConsentShown {
		t.Fatalf("WasConsentShown = true, want false when no page was shown")
	}
	if consent.ConsentSubject != nil {
		t.Fatalf("consent was persisted although none was required")
	}
}

// TestHandleConsentRequiredUnderPromptNone covers the prompt=none case: a required
// consent decision cannot be collected without an interaction, so it ends in a
// consent_required error with nothing shown and nothing persisted.
func TestHandleConsentRequiredUnderPromptNone(t *testing.T) {
	t.Parallel()

	consent := common.NewMockConsentService()
	consent.RequiresConsentResult = true
	req := consentRequest(t)
	req.PromptModes = []string{gois.PromptModesNone}
	g := consentGenerator(consent)

	resp := g.HandleConsent(req, nil)

	if !errors.Is(resp.Error, gois.AuthorizeErrorsConsentRequired) {
		t.Fatalf("Error = %v, want consent_required", resp.Error)
	}
	if req.WasConsentShown {
		t.Fatalf("WasConsentShown = true, want false under prompt=none")
	}
	if consent.ConsentSubject != nil {
		t.Fatalf("consent was persisted under prompt=none")
	}
}

// TestHandleConsentDeniesUnsatisfactoryGrant covers the two rejection paths for a
// submitted answer: an empty/denied grant, and a grant missing a required scope.
// Both deny access, both record that the page was shown, and neither persists.
func TestHandleConsentDeniesUnsatisfactoryGrant(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		consent *messages.ConsentResponse
	}{
		"empty grant is a denial": {
			consent: &messages.ConsentResponse{ScopesValuesConsented: []string{}, RememberConsent: false},
		},
		"grant missing a required scope is denied": {
			consent: &messages.ConsentResponse{ScopesValuesConsented: []string{"read"}},
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consent := common.NewMockConsentService()
			consent.RequiresConsentResult = true
			req := consentRequest(t)
			g := consentGenerator(consent)

			resp := g.HandleConsent(req, tc.consent)

			if !errors.Is(resp.Error, gois.AuthorizeErrorsAccessDenied) {
				t.Fatalf("Error = %v, want access_denied", resp.Error)
			}
			if !req.WasConsentShown {
				t.Fatalf("WasConsentShown = false, want true once an answer was processed")
			}
			if consent.ConsentSubject != nil {
				t.Fatalf("a denied grant was persisted")
			}
		})
	}
}

// TestHandleConsentFiltersGrantedSubset covers the allow path: a valid consented
// subset narrows the validated resources to the granted scopes, records the page
// as shown, returns a non-consent result, and — with remembering disallowed by the
// client — persists nothing.
func TestHandleConsentFiltersGrantedSubset(t *testing.T) {
	t.Parallel()

	consent := common.NewMockConsentService()
	consent.RequiresConsentResult = true
	req := consentRequest(t)
	req.Client.AllowRememberConsent = false
	g := consentGenerator(consent)

	answer := &messages.ConsentResponse{
		ScopesValuesConsented: []string{"openid", "read"},
		RememberConsent:       false,
	}

	resp := g.HandleConsent(req, answer)

	if resp.IsError() {
		t.Fatalf("did not expect an error, got %v", resp.Error)
	}
	if resp.IsConsent {
		t.Fatalf("IsConsent = true, want false once consent is granted")
	}
	if !req.WasConsentShown {
		t.Fatalf("WasConsentShown = false, want true")
	}

	identity := req.ValidatedResources.Resources.IdentityResources()
	if len(identity) != 1 || identity[0].Name != "openid" {
		t.Fatalf("identity resources = %v, want exactly [openid]", identity)
	}
	apiScopes := req.ValidatedResources.Resources.ApiScopes()
	if len(apiScopes) != 1 || apiScopes[0].Name != "read" {
		t.Fatalf("api scopes = %v, want exactly [read]", apiScopes)
	}

	if consent.ConsentSubject != nil {
		t.Fatalf("consent was persisted although the client disallows remembering")
	}
}

// TestHandleConsentPersistenceGatedByClient covers the persistence gate: when the
// client allows remembering, a granted decision is written through the update
// surface — the full consented set when remembered, an empty set when not.
func TestHandleConsentPersistenceGatedByClient(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		remember   bool
		wantScopes []string
	}{
		"remembered consent persists the granted scopes": {
			remember:   true,
			wantScopes: []string{"openid", "read"},
		},
		"unremembered consent persists an empty set": {
			remember:   false,
			wantScopes: []string{},
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consent := common.NewMockConsentService()
			consent.RequiresConsentResult = true
			req := consentRequest(t)
			req.Client.AllowRememberConsent = true
			g := consentGenerator(consent)

			answer := &messages.ConsentResponse{
				ScopesValuesConsented: []string{"openid", "read"},
				RememberConsent:       tc.remember,
			}

			g.HandleConsent(req, answer)

			if consent.ConsentSubject != req.Subject {
				t.Fatalf("persisted subject = %p, want %p", consent.ConsentSubject, req.Subject)
			}
			if consent.ConsentClient != req.Client {
				t.Fatalf("persisted client = %p, want %p", consent.ConsentClient, req.Client)
			}
			if !sameStringSet(consent.ConsentScopes, tc.wantScopes) {
				t.Fatalf("persisted scopes = %v, want set %v", consent.ConsentScopes, tc.wantScopes)
			}
		})
	}
}

// sameStringSet reports whether two string slices hold the same elements ignoring
// order (the validated-resource maps do not preserve a stable order).
func sameStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	counts := map[string]int{}
	for _, v := range got {
		counts[v]++
	}
	for _, v := range want {
		counts[v]--
		if counts[v] < 0 {
			return false
		}
	}
	return true
}
