// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import config_options "github.com/gonewx/wicket/config/options"

type TestWicketOptions struct{}

func NewTestWicketOptions() *TestWicketOptions {
	return &TestWicketOptions{}
}
func (o *TestWicketOptions) Create() *config_options.WicketOptions {
	opts := config_options.NewWicketOptions()
	opts.IssuerUri = "https://wicket.local"
	return opts
}
