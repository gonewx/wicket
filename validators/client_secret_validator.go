// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"net/http"

	"github.com/gonewx/wicket/validators/models"
)

// ClientSecretValidator for handling client authentication
type ClientSecretValidator interface {
	// Tries to authenticate a client based on the incoming request
	Validate(req *http.Request) *models.ClientSecretValidationResult
}
