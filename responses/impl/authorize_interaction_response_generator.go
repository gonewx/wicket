// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// AuthorizeInteractionResponseGenerator creates authorization interaction responses.
// input: validated authorize request/consent -> behavior: classify user interaction need -> output: interaction response.
type AuthorizeInteractionResponseGenerator struct{}

func NewAuthorizeInteractionResponseGenerator(
	logger *slog.Logger,
	clock services.SystemClock,
	options *config_options.WicketOptions,
	consent services.ConsentService,
	profile services.ProfileService,
	urls services.ServerUrls,
	store storage.AuthorizationParametersMessageStore,
) *AuthorizeInteractionResponseGenerator {
	return &AuthorizeInteractionResponseGenerator{}
}

func (g *AuthorizeInteractionResponseGenerator) Handle(req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse {
	return responses_models.NewInteractionResponse()
}

func (g *AuthorizeInteractionResponseGenerator) HandleLogin(req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
	return &responses_models.InteractionResponse{IsLogin: true}
}

func (g *AuthorizeInteractionResponseGenerator) HandleConsent(req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse {
	return &responses_models.InteractionResponse{IsConsent: true}
}
