// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// accountCreationSuppressedPrompts are the prompt values the account creation
// page satisfies: creating an account is a fresh authentication, so neither
// the create prompt nor a login or account selection prompt is raised again
// when the user returns. consent is not an authentication and stays.
var accountCreationSuppressedPrompts = []string{
	wicket.PromptModesCreate,
	wicket.PromptModesLogin,
	wicket.PromptModesSelectAccount,
}

// ServeAccountCreation records the URL of the host's account creation page.
// Handle then redirects a request with the create prompt to that page. An
// empty url leaves the create prompt ignored.
func (g *AuthorizeInteractionResponseGenerator) ServeAccountCreation(url string) {
	g.accountCreationUrl = url
}

// handleAccountCreation returns the redirect to the account creation page
// when the request asks for it, and nil otherwise. The values the page
// satisfies are suppressed, so the request the page returns to does not
// raise them again.
func (g *AuthorizeInteractionResponseGenerator) handleAccountCreation(req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
	if g.accountCreationUrl == "" || !slices.Contains(req.PromptModes, wicket.PromptModesCreate) {
		return nil
	}

	suppressed := slices.Clone(req.SuppressedPromptModes)
	for _, prompt := range req.PromptModes {
		if slices.Contains(accountCreationSuppressedPrompts, prompt) && !slices.Contains(suppressed, prompt) {
			suppressed = append(suppressed, prompt)
		}
	}
	req.SuppressedPromptModes = suppressed
	if req.Raw != nil {
		req.Raw.Set(wicket.SuppressedPrompt, strings.Join(suppressed, " "))
	}
	req.PromptModes = slices.DeleteFunc(slices.Clone(req.PromptModes), func(prompt string) bool {
		return slices.Contains(accountCreationSuppressedPrompts, prompt)
	})

	return &responses_models.InteractionResponse{RedirectUrl: g.accountCreationUrl}
}
