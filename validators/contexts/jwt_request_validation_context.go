// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package validators_contexts

import storage_models "github.com/gonewx/wicket/storage/models"

type JwtRequestValidationContext struct {
	Client              *storage_models.Client
	JwtTokenString      string
	StrictJarValidation *bool
	IncludeJti          bool
}
