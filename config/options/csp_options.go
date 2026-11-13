// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

import "github.com/gonewx/wicket"

// CspOptions Options for Content Security Policy
type CspOptions struct {
	Level               wicket.CspLevel
	AddDeprecatedHeader bool
}

func NewCspOptions() *CspOptions {
	return &CspOptions{
		Level:               wicket.CspLevelTwo,
		AddDeprecatedHeader: true,
	}
}
