// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauthorization

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func withRequestedAcr(p *integration_common.WicketPipeline) {
	p.Root.ServerConfig().RequireRequestedAcr()
}

// loginWithAcr signs bob in on the login page target with the given acr and
// returns where the login page sends the browser back.
func (s *scene) loginWithAcr(target string, acr string) string {
	s.t.Helper()
	user := models.NewLocalUser(models.WithLocalUserSubjectId("bob"))
	user.AdditionalClaims = []*claims.Claim{claims.NewClaim(
		claims.WithClaimType(wicket.JwtClaimTypesAuthenticationContextClassReference),
		claims.WithClaimValue(acr),
	)}
	principal, err := user.CreatePrincipal()
	if err != nil {
		s.t.Fatal(err)
	}
	s.pipeline.Subject = principal
	status, location := s.browse(target)
	if status != http.StatusFound {
		s.t.Fatalf("login page answered %d", status)
	}
	return location
}

// TestPushedRequestedAcr pushes acr_values=urn:a and signs in on the login
// page with the given acr: a matching acr is issued a code, any other is
// answered at the client with unmet_authentication_requirements. Either way
// the pushed request is consumed.
func TestPushedRequestedAcr(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		acr       string
		wantError bool
	}{
		"satisfied":     {acr: "urn:a"},
		"not satisfied": {acr: "urn:low", wantError: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newScene(t, sceneOptions{configure: withRequestedAcr})

			values := authorizationParameters(parClient)
			values.Set(wicket.AuthorizeRequestAcrValues, "urn:a")
			r := s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, values, parClient, nil)
			if r.status != http.StatusCreated {
				t.Fatalf("push: status %d body %s", r.status, r.body)
			}
			requestURI := r.field("request_uri")

			first := s.authorize(s.authorizeUrl(parClient, requestURI))
			if first.login == "" {
				t.Fatalf("outcome %+v, want the login page", first)
			}
			returned := returnParameters(t, first.login)
			assertOnlyHandleParameters(t, returned)
			if got := returned.Get(wicket.SuppressedPrompt); got != wicket.PromptModesLogin {
				t.Fatalf("suppressed_prompt = %q", got)
			}

			back := s.loginWithAcr(first.login, tc.acr)
			s.pipeline.LoginWasCalled = false
			status, location := s.browse(back)
			o := s.follow(status, location)
			if s.pipeline.LoginWasCalled || o.login != "" {
				t.Fatalf("the login page was reached twice: %+v", o)
			}
			if tc.wantError {
				if o.clientError != wicket.AuthorizeErrorsUnmetAuthenticationRequirements.Error() || o.code != "" || o.pageError != "" {
					t.Fatalf("outcome %+v, want unmet_authentication_requirements at the client", o)
				}
				parsed, err := url.Parse(location)
				if err != nil || parsed.Query().Get("state") != "pushed-state" {
					t.Fatalf("client response %q lacks the state", location)
				}
			} else if o.code == "" || o.clientError != "" {
				t.Fatalf("outcome %+v, want a code", o)
			}
			if s.record(requestURI) != nil {
				t.Fatal("the pushed request was not consumed")
			}
		})
	}
}
