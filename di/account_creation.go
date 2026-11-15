// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/gonewx/godi"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/responses"
	responses_impl "github.com/gonewx/wicket/responses/impl"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

// SetAccountCreationUrl declares the host's account creation page. An
// authorize request with prompt=create is then redirected to that page with
// the return URL parameter of the user interaction options; the page creates
// the account, signs the user in and returns to the return URL. Discovery
// advertises prompt_values_supported, create included, while the
// authorization endpoint is advertised. Without the declaration
// prompt=create is refused with invalid_request.
//
// url is a local path (starting with "/" or "~/") or an absolute http or
// https URL with a host; surrounding white space is removed. Any other value
// panics, as does a call after Freeze. A repeated call replaces the URL.
func (c *ServerConfig) SetAccountCreationUrl(url string) {
	if c.frozen {
		panic("SetAccountCreationUrl must not be called after Freeze")
	}
	value := strings.TrimSpace(url)
	if !validAccountCreationUrl(value) {
		panic(fmt.Sprintf("SetAccountCreationUrl: %q is neither a local path nor an absolute http or https URL", url))
	}
	c.accountCreationUrl = value
}

// AccountCreationUrl returns the declared account creation page, or "" while
// none was declared.
func (c *ServerConfig) AccountCreationUrl() string {
	if c == nil {
		return ""
	}
	return c.accountCreationUrl
}

func validAccountCreationUrl(value string) bool {
	if value == "" {
		return false
	}
	if utils.IsLocalUrl(value) {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}

// accountCreationUrlFromProvider reads the declared account creation page.
func accountCreationUrlFromProvider(p godi.Provider) string {
	if cfg, ok := godi.Get[*ServerConfig](p); ok {
		return cfg.AccountCreationUrl()
	}
	return ""
}

// authorizeRequestValidatorFromProvider yields the authorize request
// validator wrapped by the create prompt decorator. The decorator is always
// in place: without an account creation page it refuses prompt=create.
//
// The wrapped validator is built exactly as the core registration builds it;
// a setter added there must be added here as well.
func authorizeRequestValidatorFromProvider(p godi.Provider) validators.AuthorizeRequestValidator {
	validator := validators_impl.NewAuthorizeRequestValidator(
		godi.GetRequired[*slog.Logger](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[services.IssuerNameService](p),
		godi.GetRequired[storage.ClientStore](p),
		godi.GetRequired[services.JwtRequestUriHttpClient](p),
		godi.GetRequired[validators.JwtRequestValidator](p),
		godi.GetRequired[validators.RedirectUriValidator](p),
		godi.GetRequired[validators.ResourceValidator](p),
		userSessionFromProvider(p),
		godi.GetRequired[validators.CustomAuthorizeRequestValidator](p),
	)
	if godi.GetRequired[*ServerConfig](p).PushedAuthorizationRequestsEnabled() {
		validator.SetPushedAuthorization(validators_impl.NewAuthorizeRequestPushedStage(pushedAuthorizationFromProvider(p)))
	}
	if godi.GetRequired[*ServerConfig](p).DPoPEnabled() {
		validator.SetDPoPKeyBinding()
	}
	return validators_impl.NewAuthorizePromptCreateValidator(validator, accountCreationUrlFromProvider(p) != "")
}

// authorizeInteractionResponseGeneratorFromProvider yields the interaction
// response generator, serving the declared account creation page and
// enforcing the requested acr_values while that option is declared.
//
// The generator is built exactly as the core registration builds it; a
// setter added there must be added here as well.
func authorizeInteractionResponseGeneratorFromProvider(p godi.Provider) responses.AuthorizeInteractionResponseGenerator {
	generator := responses_impl.NewAuthorizeInteractionResponseGenerator(
		godi.GetRequired[*slog.Logger](p),
		godi.GetRequired[services.SystemClock](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[services.ConsentService](p),
		godi.GetRequired[services.ProfileService](p),
		godi.GetRequired[services.ServerUrls](p),
		godi.GetRequired[*ServerConfig](p).AuthorizationParametersMessageStore(),
	)
	if url := accountCreationUrlFromProvider(p); url != "" {
		generator.ServeAccountCreation(url)
	}
	if godi.GetRequired[*ServerConfig](p).RequestedAcrRequired() {
		generator.RequireRequestedAcr()
	}
	return generator
}
