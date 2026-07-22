// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/oidcverify"
	"github.com/gonewx/wicket/services"
)

func registerOIDCVerify() {
	var r godi.Registry

	godi.AddSingletonFactory[*oidcverify.ProviderConfig](&r, func(p godi.Provider) *oidcverify.ProviderConfig {
		return &oidcverify.ProviderConfig{}
	})

	godi.AddSingletonFactory[oidcverify.Verifier](&r, func(p godi.Provider) oidcverify.Verifier {
		cfg := godi.GetRequired[*oidcverify.ProviderConfig](p)
		clock := godi.GetRequired[services.SystemClock](p)
		v, err := oidcverify.NewVerifier(context.Background(), *cfg, clock)
		if err != nil {
			panic(err)
		}
		return v
	})
}
