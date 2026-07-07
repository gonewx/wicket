// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import config_options "github.com/gonewx/wicket/config/options"

type TestIdentityServerOptions struct{}

func NewTestIdentityServerOptions() *TestIdentityServerOptions {
	return &TestIdentityServerOptions{}
}
func (o *TestIdentityServerOptions) Create() *config_options.IdentityServerOptions {
	opts := config_options.NewIdentityServerOptions()
	opts.IssuerUri = "https://idsvr.com"
	return opts
}
