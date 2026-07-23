// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/oidcverify"
)

func registerOIDCVerify() {
	var r godi.Registry

	godi.AddSingletonFactory[*oidcverify.ProviderConfig](&r, func(p godi.Provider) *oidcverify.ProviderConfig {
		return &oidcverify.ProviderConfig{}
	})
}
