// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package authorize

import (
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type StubAuthorizeInteractionResponseGenerator struct {
	Response *responses_models.InteractionResponse
}

func NewStubAuthorizeInteractionResponseGenerator() *StubAuthorizeInteractionResponseGenerator {
	return &StubAuthorizeInteractionResponseGenerator{
		Response: responses_models.NewInteractionResponse(),
	}
}

func (h *StubAuthorizeInteractionResponseGenerator) Handle(req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) (resp *responses_models.InteractionResponse) {
	return h.Response
}

func (h *StubAuthorizeInteractionResponseGenerator) HandleLogin(req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
	return nil
}

func (h *StubAuthorizeInteractionResponseGenerator) HandleConsent(req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse {
	return nil
}
