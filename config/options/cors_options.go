// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

import (
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/utils"
)

// CorsOptions Options for CORS
type CorsOptions struct {
	//CorsPolicyName Gets or sets the name of the cors policy.
	CorsPolicyName string
	//PreflightCacheDuration The value to be used in the preflight `Access-Control-Max-Age` response header.
	PreflightCacheDuration *time.Duration
	//CorsPaths Gets or sets the cors paths.
	CorsPaths []string
}

func NewCorsOptions() *CorsOptions {
	return &CorsOptions{
		CorsPolicyName: wicket.WicketName,
		CorsPaths: utils.Select(wicket.CorsPaths, func(x string) string {
			return utils.EnsureLeadingSlash(x)
		}),
	}
}
