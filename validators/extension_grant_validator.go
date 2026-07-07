// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

// ExtensionGrantValidator Handles validation of token requests using custom grant types
type ExtensionGrantValidator interface {
	/// Validates the custom grant request.
	Validate(ctx *validators_contexts.ExtensionGrantValidationContext) error

	/// Returns the grant type this validator can deal with
	GrantType() string
}
