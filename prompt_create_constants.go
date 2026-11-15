// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket

// Account creation prompt (OpenID Connect Prompt Create 1.0).
const (
	// PromptModesCreate is the prompt value with which a client asks the
	// provider to show its account creation experience instead of the login
	// experience.
	PromptModesCreate = "create"
	// DiscoveryPromptValuesSupported is the discovery metadata name listing
	// the prompt values the provider supports.
	DiscoveryPromptValuesSupported = "prompt_values_supported"
)
