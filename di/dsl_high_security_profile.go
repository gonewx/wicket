// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"github.com/gonewx/godi"
	config_options "github.com/gonewx/wicket/config/options"
	optspkg "github.com/gonewx/wicket/di/options"
)

// registerHighSecurityProfile binds the materialized WicketOptions to the
// server configuration. The options are materialized while the root
// container is built, before the host can declare the high security
// profile, so the post-configuration only records the value; Freeze turns
// on the protocol options the profile requires (see
// high_security_profile.go).
func registerHighSecurityProfile() {
	var r godi.Registry

	godi.AddSingletonFactory[optspkg.PostConfigureOptions[*config_options.WicketOptions]](&r, func(p godi.Provider) optspkg.PostConfigureOptions[*config_options.WicketOptions] {
		return highSecurityProfileOptionsBinding{config: godi.GetRequired[*ServerConfig](p)}
	})
}

// highSecurityProfileOptionsBinding records every WicketOptions value it
// post-configures with the server configuration.
type highSecurityProfileOptionsBinding struct {
	config *ServerConfig
}

func (b highSecurityProfileOptionsBinding) PostConfigure(_ string, options *config_options.WicketOptions) error {
	b.config.bindHighSecurityProfileOptions(options)
	return nil
}
