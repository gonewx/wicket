// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package responses

import (
	"context"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type AuthorizeInteractionResponseGenerator interface {
	Handle(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) (resp *responses_models.InteractionResponse)

	HandleLogin(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse

	HandleConsent(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse
}
