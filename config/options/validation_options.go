// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

// ValidationOptions contains settings that affect some of the default validation behavior.
type ValidationOptions struct {
	//  Collection of URI scheme prefixes that should never be used as custom URI schemes in the redirect_uri passed to tha authorize endpoint.
	InvalidRedirectUriPrefixes []string
}

func NewValidationOptions() *ValidationOptions {
	return &ValidationOptions{
		InvalidRedirectUriPrefixes: []string{
			"javascript:",
			"file:",
			"data:",
			"mailto:",
			"ftp:",
			"blob:",
			"about:",
			"ssh:",
			"tel:",
			"view-source:",
			"ws:",
			"wss:",
		},
	}
}
