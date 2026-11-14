// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package validators

// ClientFeatureDeclarations reports the features the assembly declared
// enabled that client metadata can require.
type ClientFeatureDeclarations interface {
	// PrivateKeyJwtEnabled reports whether private_key_jwt client
	// authentication is enabled in this assembly.
	PrivateKeyJwtEnabled() bool
}
