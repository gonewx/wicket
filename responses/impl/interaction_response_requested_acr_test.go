// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

var requestedAcrClock = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

// acrSubject builds a local subject authenticated now whose session carries
// the given acr claim value; nil leaves the claim out.
func acrSubject(t *testing.T, acr any) *claims.ClaimsPrincipal {
	t.Helper()
	authTime := requestedAcrClock
	user := models.NewLocalUser(models.WithLocalUserSubjectId("123"))
	user.IdentityProvider = wicket.LocalIdentityProvider
	user.AuthenticationTime = &authTime
	if acr != nil {
		user.AdditionalClaims = []*claims.Claim{claims.NewClaim(
			claims.WithClaimType(wicket.JwtClaimTypesAuthenticationContextClassReference),
			claims.WithClaimValue(acr),
		)}
	}
	principal, err := user.CreatePrincipal()
	if err != nil {
		t.Fatalf("create subject: %v", err)
	}
	return principal
}

func TestHandleRequestedAcr(t *testing.T) {
	t.Parallel()

	type outcome int
	const (
		issue outcome = iota
		login
		unmet
		loginRequired
	)

	cases := map[string]struct {
		off            bool
		anonymous      bool
		acr            any
		acrValues      []string
		prompts        []string
		suppressed     []string
		rawSuppressed  string
		want           outcome
		wantSuppressed string
	}{
		"off and not satisfied": {
			off: true, acrValues: []string{"urn:a"},
			want: issue,
		},
		"off and anonymous": {
			off: true, anonymous: true, acrValues: []string{"urn:a"},
			want: login,
		},
		"off under prompt=none": {
			off: true, acr: "urn:low", acrValues: []string{"urn:a"}, prompts: []string{"none"},
			want: issue,
		},
		"satisfied": {
			acr: "urn:a", acrValues: []string{"urn:b", "urn:a"},
			want: issue,
		},
		"no acr_values": {
			acr:  "urn:low",
			want: issue,
		},
		"not satisfied steps up": {
			acr: "urn:low", acrValues: []string{"urn:a"},
			want: login, wantSuppressed: "login",
		},
		"session without acr steps up": {
			acrValues: []string{"urn:a"},
			want:      login, wantSuppressed: "login",
		},
		"non text acr is no acr": {
			acr: 7, acrValues: []string{"7"},
			want: login, wantSuppressed: "login",
		},
		"step up joins earlier suppressed values": {
			acr: "urn:low", acrValues: []string{"urn:a"}, suppressed: []string{"consent"},
			want: login, wantSuppressed: "consent login",
		},
		"empty acr value is not an acr value": {
			acrValues: []string{"urn:a", ""},
			want:      login, wantSuppressed: "login",
		},
		"only an empty acr value": {
			acrValues: []string{""},
			want:      issue,
		},
		"unknown suppressed value is dropped": {
			acr: "urn:low", acrValues: []string{"urn:a"}, rawSuppressed: "foo",
			want: login, wantSuppressed: "login",
		},
		"suppressed none is dropped": {
			acr: "urn:low", acrValues: []string{"urn:a"}, rawSuppressed: "none",
			want: login, wantSuppressed: "login",
		},
		"validated suppressed none is dropped": {
			acr: "urn:low", acrValues: []string{"urn:a"}, suppressed: []string{"none"},
			want: login, wantSuppressed: "login",
		},
		"suppressed create is kept": {
			acr: "urn:low", acrValues: []string{"urn:a"}, suppressed: []string{"create"},
			want: login, wantSuppressed: "create login",
		},
		"after the login, not satisfied": {
			acr: "urn:low", acrValues: []string{"urn:a"}, suppressed: []string{"login"},
			want: unmet, wantSuppressed: "login",
		},
		"after the login, satisfied": {
			acr: "urn:a", acrValues: []string{"urn:a"}, suppressed: []string{"login"},
			want: issue, wantSuppressed: "login",
		},
		"anonymous is marked": {
			anonymous: true, acrValues: []string{"urn:a"},
			want: login, wantSuppressed: "login",
		},
		"anonymous without acr_values is not marked": {
			anonymous: true,
			want:      login,
		},
		"prompt=none not satisfied": {
			acr: "urn:low", acrValues: []string{"urn:a"}, prompts: []string{"none"},
			want: unmet,
		},
		"prompt=none anonymous": {
			anonymous: true, acrValues: []string{"urn:a"}, prompts: []string{"none"},
			want: loginRequired,
		},
		"prompt=none satisfied": {
			acr: "urn:a", acrValues: []string{"urn:a"}, prompts: []string{"none"},
			want: issue,
		},
		"prompt=login": {
			acr: "urn:a", acrValues: []string{"urn:a"}, prompts: []string{"login"},
			want: login, wantSuppressed: "login",
		},
		"prompt=login with account selection": {
			acr: "urn:a", acrValues: []string{"urn:a"}, prompts: []string{"login", "select_account"},
			want: login, wantSuppressed: "login select_account",
		},
		"only hint prefixes": {
			acrValues: []string{"idp:local", "tenant:t"},
			want:      issue,
		},
		"hint prefixes are not acr values": {
			acr: "urn:a", acrValues: []string{"idp:local", "tenant:t", "urn:a"},
			want: issue,
		},
		"hint prefix never matches the session acr": {
			acr: "tenant:t", acrValues: []string{"tenant:t", "urn:a"},
			want: login, wantSuppressed: "login",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := buildGenerator(fixedClock(requestedAcrClock), common.NewMockConsentService(), common.NewMockProfileService())
			if !tc.off {
				g.RequireRequestedAcr()
			}

			req := validators_models.NewValidatedAuthorizeRequest()
			req.Raw = url.Values{}
			if len(tc.suppressed) > 0 {
				req.Raw.Set(wicket.SuppressedPrompt, strings.Join(tc.suppressed, " "))
			}
			if tc.rawSuppressed != "" {
				req.Raw.Set(wicket.SuppressedPrompt, tc.rawSuppressed)
			}
			req.Client = storage_models.NewClient()
			req.AuthenticationContextReferenceClasses = slices.Clone(tc.acrValues)
			req.PromptModes = slices.Clone(tc.prompts)
			req.SuppressedPromptModes = slices.Clone(tc.suppressed)
			req.ValidatedResources = requestedConsentResources()
			req.Subject = claims.NewClaimsPrincipal()
			if !tc.anonymous {
				req.Subject = acrSubject(t, tc.acr)
			}

			got := g.Handle(context.Background(), req, nil)
			switch tc.want {
			case issue:
				if got.IsError() || got.IsLogin || got.IsConsent || got.IsRedirect() {
					t.Fatalf("interaction = %+v, want none", got)
				}
			case login:
				if got.IsError() || !got.IsLogin {
					t.Fatalf("interaction = %+v, want the login page", got)
				}
			case unmet:
				if !errors.Is(got.Error, wicket.AuthorizeErrorsUnmetAuthenticationRequirements) ||
					got.ErrorDescription != "requested acr_values could not be satisfied" || got.IsLogin {
					t.Fatalf("interaction = %+v, want unmet_authentication_requirements", got)
				}
			case loginRequired:
				if !errors.Is(got.Error, wicket.AuthorizeErrorsLoginRequired) {
					t.Fatalf("interaction = %+v, want login_required", got)
				}
			}
			if marker := req.Raw.Get(wicket.SuppressedPrompt); marker != tc.wantSuppressed {
				t.Fatalf("suppressed_prompt = %q, want %q", marker, tc.wantSuppressed)
			}
			if tc.wantSuppressed == "login" && tc.want == login && !slices.Contains(req.SuppressedPromptModes, wicket.PromptModesLogin) {
				t.Fatalf("SuppressedPromptModes = %v", req.SuppressedPromptModes)
			}
		})
	}
}

// TestHandleRequestedAcrStepsUpOnlyOnce follows a request through the login
// page: the first pass steps up, and the returning request, carrying the
// marker, is refused when the session still does not satisfy it.
func TestHandleRequestedAcrStepsUpOnlyOnce(t *testing.T) {
	t.Parallel()
	g := buildGenerator(fixedClock(requestedAcrClock), common.NewMockConsentService(), common.NewMockProfileService())
	g.RequireRequestedAcr()

	req := validators_models.NewValidatedAuthorizeRequest()
	req.Raw = url.Values{}
	req.Client = storage_models.NewClient()
	req.AuthenticationContextReferenceClasses = []string{"urn:a"}
	req.ValidatedResources = requestedConsentResources()
	req.Subject = acrSubject(t, "urn:low")

	if got := g.Handle(context.Background(), req, nil); !got.IsLogin {
		t.Fatalf("first pass = %+v, want the login page", got)
	}
	if got := g.Handle(context.Background(), req, nil); !errors.Is(got.Error, wicket.AuthorizeErrorsUnmetAuthenticationRequirements) {
		t.Fatalf("second pass = %+v, want unmet_authentication_requirements", got)
	}
}
