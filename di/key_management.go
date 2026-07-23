// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	config_options "github.com/gonewx/wicket/config/options"
)

// resolveAutoCreate maps the tri-state AutoCreate option: unset defaults to on so
// an enabled manager bootstraps a key; an explicit value is honoured.
func resolveAutoCreate(opts *config_options.KeyManagementOptions) bool {
	if opts.AutoCreate == nil {
		return true
	}
	return *opts.AutoCreate
}
