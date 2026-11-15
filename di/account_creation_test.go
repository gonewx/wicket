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
	"github.com/gonewx/wicket/responses"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func TestSetAccountCreationUrl(t *testing.T) {
	t.Parallel()

	accepted := map[string]string{
		"local path":            "/account/create",
		"application path":      "~/account/create",
		"https":                 "https://accounts.example/create?from=wicket",
		"http":                  "http://localhost:5000/create",
		"upper case scheme":     "HTTPS://accounts.example/create",
		"surrounding white":     "  /account/create\t",
		"local path with query": "/account/create?step=1",
	}
	for name, value := range accepted {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			cfg.SetAccountCreationUrl(value)
			if got := cfg.AccountCreationUrl(); got != strings.TrimSpace(value) {
				t.Fatalf("AccountCreationUrl() = %q", got)
			}
		})
	}

	rejected := map[string]string{
		"empty":             "",
		"white space":       "  \t",
		"other scheme":      "ftp://x",
		"no host":           "https:///create",
		"relative":          "account/create",
		"scheme only":       "https:",
		"javascript scheme": "javascript:alert(1)",
	}
	for name, value := range rejected {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			text := panicText(t, func() { NewServerConfig().SetAccountCreationUrl(value) })
			if !strings.Contains(text, "SetAccountCreationUrl") {
				t.Fatalf("panic text %q", text)
			}
		})
	}

	t.Run("last call wins", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		cfg.SetAccountCreationUrl("/first")
		cfg.SetAccountCreationUrl("https://accounts.example/second")
		if got := cfg.AccountCreationUrl(); got != "https://accounts.example/second" {
			t.Fatalf("AccountCreationUrl() = %q", got)
		}
	})
	t.Run("not declared", func(t *testing.T) {
		t.Parallel()
		if NewServerConfig().AccountCreationUrl() != "" {
			t.Fatal("declared without a call")
		}
		var nilConfig *ServerConfig
		if nilConfig.AccountCreationUrl() != "" {
			t.Fatal("a nil configuration reports a declaration")
		}
	})
}

func TestSetAccountCreationUrlPanicsAfterFreeze(t *testing.T) {
	_, cfg := newAssertionRoot(t)
	cfg.Freeze()
	text := panicText(t, func() { cfg.SetAccountCreationUrl("/account/create") })
	if !strings.Contains(text, "SetAccountCreationUrl") || !strings.Contains(text, "after Freeze") {
		t.Fatalf("panic text %q", text)
	}
}

// accountCreationRoot builds a container with one client allowed to request
// openid with the authorization code flow.
func accountCreationRoot(t *testing.T, declare func(*ServerConfig)) *Root {
	t.Helper()
	root, cfg := newAssertionRoot(t)
	client := storage_models.NewClient()
	client.ClientId = "client"
	client.RequirePkce = false
	client.RedirectUris = []string{"https://client.example/callback"}
	client.AllowedScopes = []string{"openid"}
	if err := client.SetAllowedGrantTypes([]string{wicket.GrantTypeAuthorizationCode}); err != nil {
		t.Fatalf("grant types: %v", err)
	}
	cfg.SetClients([]*storage_models.Client{client})
	cfg.SetIdentityScopes([]*storage_models.IdentityResource{storage_models.IdentityResourcesOpenId()})
	if declare != nil {
		declare(cfg)
	}
	cfg.Freeze()
	return root
}

func createPromptValues() url.Values {
	return url.Values{
		wicket.AuthorizeRequestClientId:     {"client"},
		wicket.AuthorizeRequestRedirectUri:  {"https://client.example/callback"},
		wicket.AuthorizeRequestResponseType: {wicket.ResponseTypesCode},
		wicket.AuthorizeRequestScope:        {"openid"},
		wicket.AuthorizeRequestPrompt:       {wicket.PromptModesCreate},
	}
}

func TestAuthorizeAssemblyWithoutAccountCreationRefusesCreate(t *testing.T) {
	root := accountCreationRoot(t, nil)

	validator := godi.GetRequired[validators.AuthorizeRequestValidator](root)
	decorator, ok := validator.(*validators_impl.AuthorizePromptCreateValidator)
	if !ok {
		t.Fatalf("authorize request validator is %T, want the create prompt decorator", validator)
	}
	if _, ok := decorator.Inner().(*validators_impl.AuthorizeRequestValidator); !ok || decorator.AccountCreation() {
		t.Fatalf("decorator wraps %T, account creation %v", decorator.Inner(), decorator.AccountCreation())
	}

	result := validator.Validate(context.Background(), createPromptValues(), claims.NewClaimsPrincipal(), validators.AuthorizeRequestPhaseEntry)
	if !errors.Is(result.Error, wicket.AuthorizeErrorsInvalidRequest) || result.Description != "prompt value create is not supported" {
		t.Fatalf("result = %v %q, want invalid_request", result.Error, result.Description)
	}

	values := createPromptValues()
	values.Set(wicket.AuthorizeRequestPrompt, wicket.PromptModesLogin)
	if result := validator.Validate(context.Background(), values, claims.NewClaimsPrincipal(), validators.AuthorizeRequestPhaseEntry); result.Error != nil {
		t.Fatalf("a request without create failed: %v %q", result.Error, result.Description)
	}
}

func TestAuthorizeAssemblyWithAccountCreationRedirects(t *testing.T) {
	root := accountCreationRoot(t, func(cfg *ServerConfig) { cfg.SetAccountCreationUrl("/account/create") })

	result := godi.GetRequired[validators.AuthorizeRequestValidator](root).Validate(context.Background(), createPromptValues(), claims.NewClaimsPrincipal(), validators.AuthorizeRequestPhaseEntry)
	if result.Error != nil {
		t.Fatalf("validate: %v %q", result.Error, result.Description)
	}
	request := result.ValidatedRequest
	if len(request.PromptModes) != 1 || request.PromptModes[0] != wicket.PromptModesCreate {
		t.Fatalf("PromptModes = %v", request.PromptModes)
	}

	generator := godi.GetRequired[responses.AuthorizeInteractionResponseGenerator](root)
	interaction := generator.Handle(context.Background(), request, nil)
	if interaction.RedirectUrl != "/account/create" {
		t.Fatalf("interaction = %+v, want the account creation redirect", interaction)
	}
	if got := request.Raw.Get(wicket.SuppressedPrompt); got != wicket.PromptModesCreate {
		t.Fatalf("suppressed_prompt = %q", got)
	}
}

func TestAuthorizeAssemblyWithoutAccountCreationIgnoresCreateInTheGenerator(t *testing.T) {
	root := accountCreationRoot(t, nil)

	request := validators_models.NewValidatedAuthorizeRequest()
	request.Raw = url.Values{}
	request.PromptModes = []string{wicket.PromptModesCreate}
	request.Subject = claims.NewClaimsPrincipal()
	interaction := godi.GetRequired[responses.AuthorizeInteractionResponseGenerator](root).Handle(context.Background(), request, nil)
	if interaction.IsRedirect() || !interaction.IsLogin {
		t.Fatalf("interaction = %+v, want the login page", interaction)
	}
}
