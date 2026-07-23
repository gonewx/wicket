// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

// Blank references anchor the godi-gen DSL registration functions so that static
// analysis tools (IDEs, linters, dead-code eliminators) do not flag them as unused.
// These functions are consumed by godi-gen at code-generation time, not at runtime.
var (
	_ = registerCore
	_ = registerCrypto
	_ = registerInMemory
	_ = registerPluggableServicesAndValidators
	_ = registerKeyManagement
	_ = registerOIDCVerify
	_ = registerAdditional
)
