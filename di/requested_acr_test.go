// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/responses"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func TestRequireRequestedAcr(t *testing.T) {
	t.Parallel()

	cfg := NewServerConfig()
	if cfg.RequestedAcrRequired() {
		t.Fatal("declared without a call")
	}
	cfg.RequireRequestedAcr()
	cfg.RequireRequestedAcr()
	if !cfg.RequestedAcrRequired() {
		t.Fatal("a declared option is not reported")
	}
	var nilConfig *ServerConfig
	if nilConfig.RequestedAcrRequired() {
		t.Fatal("a nil configuration reports a declaration")
	}
}

func TestRequireRequestedAcrPanicsAfterFreeze(t *testing.T) {
	_, cfg := newAssertionRoot(t)
	cfg.Freeze()
	text := panicText(t, func() { cfg.RequireRequestedAcr() })
	if !strings.Contains(text, "RequireRequestedAcr") || !strings.Contains(text, "after Freeze") {
		t.Fatalf("panic text %q", text)
	}
}

// unmetAcrRequest is a request for acr urn:a from a session that already
// went through the login page with acr urn:low.
func unmetAcrRequest(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
	t.Helper()
	user := models.NewLocalUser(models.WithLocalUserSubjectId("123"))
	user.IdentityProvider = wicket.LocalIdentityProvider
	user.AdditionalClaims = []*claims.Claim{claims.NewClaim(
		claims.WithClaimType(wicket.JwtClaimTypesAuthenticationContextClassReference),
		claims.WithClaimValue("urn:low"),
	)}
	subject, err := user.CreatePrincipal()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	request := validators_models.NewValidatedAuthorizeRequest()
	request.Raw = url.Values{wicket.SuppressedPrompt: {wicket.PromptModesLogin}}
	request.Client = storage_models.NewClient()
	request.Subject = subject
	request.AuthenticationContextReferenceClasses = []string{"urn:a"}
	request.SuppressedPromptModes = []string{wicket.PromptModesLogin}
	request.ValidatedResources = validators_models.NewResourceValidationResult()
	return request
}

func TestAuthorizeAssemblyEnforcesRequestedAcrOnlyWhenDeclared(t *testing.T) {
	cases := map[string]struct {
		declare func(*ServerConfig)
		want    bool
	}{
		"default":  {},
		"declared": {declare: func(cfg *ServerConfig) { cfg.RequireRequestedAcr() }, want: true},
		"declared with account creation": {declare: func(cfg *ServerConfig) {
			cfg.RequireRequestedAcr()
			cfg.SetAccountCreationUrl("/account/create")
		}, want: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := accountCreationRoot(t, tc.declare)
			interaction := godi.GetRequired[responses.AuthorizeInteractionResponseGenerator](root).Handle(context.Background(), unmetAcrRequest(t), nil)
			got := errors.Is(interaction.Error, wicket.AuthorizeErrorsUnmetAuthenticationRequirements)
			if got != tc.want {
				t.Fatalf("interaction = %+v, want unmet_authentication_requirements %v", interaction, tc.want)
			}
			if !tc.want && (interaction.IsError() || interaction.IsLogin) {
				t.Fatalf("default assembly interaction = %+v, want none", interaction)
			}
		})
	}
}
