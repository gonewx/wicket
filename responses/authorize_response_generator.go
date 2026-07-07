// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package responses

import (
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// AuthorizeResponseGenerator Interface for the authorize response generator
type AuthorizeResponseGenerator interface {
	Create(req *validators_models.ValidatedAuthorizeRequest) (*responses_models.AuthorizeResponse, error)
}
