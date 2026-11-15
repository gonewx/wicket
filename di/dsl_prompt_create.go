// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/validators"
)

// registerPromptCreate replaces the authorize request validator and the
// interaction response generator registrations with factories that serve the
// create prompt from the declared account creation page. Being registered
// later, they take precedence.
func registerPromptCreate() {
	var r godi.Registry

	godi.AddTransientFactory[validators.AuthorizeRequestValidator](&r, authorizeRequestValidatorFromProvider)
	godi.AddTransientFactory[responses.AuthorizeInteractionResponseGenerator](&r, authorizeInteractionResponseGeneratorFromProvider)
}
