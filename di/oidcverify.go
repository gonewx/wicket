// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

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
