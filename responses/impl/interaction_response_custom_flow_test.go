// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

var customFlowClock = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// TestHandlePassesThroughCustomRedirect covers the override seam: a substituted
// login stage that returns a redirect is passed through verbatim when no prompt
// restriction applies.
func TestHandlePassesThroughCustomRedirect(t *testing.T) {
	t.Parallel()

	g := buildGenerator(fixedClock(customFlowClock), common.NewMockConsentService(), common.NewMockProfileService())
	g.loginHandler = func(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
		return &responses_models.InteractionResponse{RedirectUrl: "/custom"}
	}

	req := validators_models.NewValidatedAuthorizeRequest()
	req.Subject = localSubject(t, nil)

	resp := g.Handle(context.Background(), req, nil)

	if !resp.IsRedirect() {
		t.Fatalf("IsRedirect() = false, want true")
	}
	if resp.RedirectUrl != "/custom" {
		t.Fatalf("RedirectUrl = %q, want /custom", resp.RedirectUrl)
	}
}

// TestHandlePromptNoneClassifiesCustomLoginStages covers the override seam under
// prompt=none: a custom login indication becomes login_required, and a custom
// redirect becomes interaction_required with the redirect cleared.
func TestHandlePromptNoneClassifiesCustomLoginStages(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		stage   func(context.Context, *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse
		wantErr error
	}{
		"custom login becomes login_required": {
			stage: func(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
				return &responses_models.InteractionResponse{IsLogin: true}
			},
			wantErr: wicket.AuthorizeErrorsLoginRequired,
		},
		"custom redirect becomes interaction_required": {
			stage: func(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
				return &responses_models.InteractionResponse{RedirectUrl: "/custom"}
			},
			wantErr: wicket.AuthorizeErrorsInteractionRequired,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := buildGenerator(fixedClock(customFlowClock), common.NewMockConsentService(), common.NewMockProfileService())
			g.loginHandler = tc.stage

			req := validators_models.NewValidatedAuthorizeRequest()
			req.PromptModes = []string{wicket.PromptModesNone}

			resp := g.Handle(context.Background(), req, nil)

			if !errors.Is(resp.Error, tc.wantErr) {
				t.Fatalf("Error = %v, want %v", resp.Error, tc.wantErr)
			}
			if resp.IsRedirect() {
				t.Fatalf("RedirectUrl = %q, want empty under prompt=none", resp.RedirectUrl)
			}
		})
	}
}

// TestHandlePromptNoneClassifiesCustomConsentStage covers the override seam for the
// consent stage: once login passes, a custom consent indication under prompt=none
// becomes consent_required.
func TestHandlePromptNoneClassifiesCustomConsentStage(t *testing.T) {
	t.Parallel()

	g := buildGenerator(fixedClock(customFlowClock), common.NewMockConsentService(), common.NewMockProfileService())
	g.consentHandler = func(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse {
		return &responses_models.InteractionResponse{IsConsent: true}
	}

	req := validators_models.NewValidatedAuthorizeRequest()
	req.PromptModes = []string{wicket.PromptModesNone}
	req.Subject = localSubject(t, nil)
	req.Client = storage_models.NewClient()

	resp := g.Handle(context.Background(), req, nil)

	if !errors.Is(resp.Error, wicket.AuthorizeErrorsConsentRequired) {
		t.Fatalf("Error = %v, want consent_required", resp.Error)
	}
}
