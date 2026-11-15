// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

var accountCreationClock = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func TestHandleRedirectsCreatePromptToAccountCreation(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		prompts        []string
		suppressed     []string
		authenticated  bool
		wantPrompts    []string
		wantSuppressed []string
	}{
		"anonymous": {
			prompts:        []string{"create"},
			wantPrompts:    []string{},
			wantSuppressed: []string{"create"},
		},
		"signed in": {
			prompts:        []string{"create"},
			authenticated:  true,
			wantPrompts:    []string{},
			wantSuppressed: []string{"create"},
		},
		"with consent": {
			prompts:        []string{"create", "consent"},
			wantPrompts:    []string{"consent"},
			wantSuppressed: []string{"create"},
		},
		"with login and account selection": {
			prompts:        []string{"select_account", "create", "login"},
			wantPrompts:    []string{},
			wantSuppressed: []string{"select_account", "create", "login"},
		},
		"joins earlier suppressed values": {
			prompts:        []string{"create", "login"},
			suppressed:     []string{"consent", "login"},
			wantPrompts:    []string{},
			wantSuppressed: []string{"consent", "login", "create"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := buildGenerator(fixedClock(accountCreationClock), common.NewMockConsentService(), common.NewMockProfileService())
			g.ServeAccountCreation("/account/create")
			loginCalled := false
			g.loginHandler = func(context.Context, *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
				loginCalled = true
				return nil
			}

			req := validators_models.NewValidatedAuthorizeRequest()
			req.Raw = url.Values{wicket.AuthorizeRequestPrompt: {"create"}}
			req.PromptModes = slices.Clone(tc.prompts)
			req.SuppressedPromptModes = slices.Clone(tc.suppressed)
			req.Subject = claims.NewClaimsPrincipal()
			if tc.authenticated {
				req.Subject = localSubject(t, &accountCreationClock)
			}

			resp := g.Handle(context.Background(), req, nil)

			if !resp.IsRedirect() || resp.RedirectUrl != "/account/create" {
				t.Fatalf("response = %+v, want the account creation redirect", resp)
			}
			if loginCalled {
				t.Fatal("the login stage ran")
			}
			if !slices.Equal(req.PromptModes, tc.wantPrompts) {
				t.Fatalf("PromptModes = %v, want %v", req.PromptModes, tc.wantPrompts)
			}
			if !slices.Equal(req.SuppressedPromptModes, tc.wantSuppressed) {
				t.Fatalf("SuppressedPromptModes = %v, want %v", req.SuppressedPromptModes, tc.wantSuppressed)
			}
			if got := req.Raw[wicket.SuppressedPrompt]; len(got) != 1 || got[0] != strings.Join(tc.wantSuppressed, " ") {
				t.Fatalf("raw suppressed_prompt = %v, want %q", got, strings.Join(tc.wantSuppressed, " "))
			}
		})
	}
}

func TestHandleIgnoresCreatePromptWithoutAccountCreation(t *testing.T) {
	t.Parallel()

	g := buildGenerator(fixedClock(accountCreationClock), common.NewMockConsentService(), common.NewMockProfileService())
	req := validators_models.NewValidatedAuthorizeRequest()
	req.Raw = url.Values{wicket.AuthorizeRequestPrompt: {"create"}}
	req.PromptModes = []string{"create"}
	req.Subject = claims.NewClaimsPrincipal()

	resp := g.Handle(context.Background(), req, nil)

	if resp.IsRedirect() || !resp.IsLogin {
		t.Fatalf("response = %+v, want the login page of the unchanged flow", resp)
	}
	if !slices.Equal(req.PromptModes, []string{"create"}) || req.SuppressedPromptModes != nil {
		t.Fatalf("prompts changed: %v / %v", req.PromptModes, req.SuppressedPromptModes)
	}
	if _, ok := req.Raw[wicket.SuppressedPrompt]; ok {
		t.Fatal("suppressed_prompt written")
	}
}

func TestHandleWithoutCreatePromptKeepsTheFlow(t *testing.T) {
	t.Parallel()

	g := buildGenerator(fixedClock(accountCreationClock), common.NewMockConsentService(), common.NewMockProfileService())
	g.ServeAccountCreation("/account/create")
	req := validators_models.NewValidatedAuthorizeRequest()
	req.Raw = url.Values{wicket.AuthorizeRequestPrompt: {"login"}}
	req.PromptModes = []string{"login"}
	req.OriginalPromptModes = []string{"login"}
	req.Subject = localSubject(t, &accountCreationClock)

	resp := g.Handle(context.Background(), req, nil)

	if resp.IsRedirect() || !resp.IsLogin {
		t.Fatalf("response = %+v, want the login page", resp)
	}
	if slices.Contains(req.Raw[wicket.SuppressedPrompt], wicket.PromptModesCreate) {
		t.Fatal("create suppressed without a create prompt")
	}
}
