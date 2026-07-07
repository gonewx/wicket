// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"net/http"

	"github.com/gonewx/wicket/models"
)

// SecretsListParser Parser for finding the best secret in an Enumerable List
type SecretParser interface {
	// Tries to find the best secret on the context that can be used for authentication
	Parse(request *http.Request) (*models.ParsedSecret, error)

	// Returns the authentication method name that this parser implements
	AuthenticationMethod() string
}
