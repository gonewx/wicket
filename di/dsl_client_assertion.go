// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"log/slog"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/validators"
)

// registerClientAssertion wires private_key_jwt client authentication. The
// singletons registered here are built while the root container is built,
// before the host can declare the feature, so none of them reads the
// enablement or the options while it is constructed: the replay registry
// wrapper materializes its seam on first use, and the key source reads the
// options through a function on every lookup. The verifier and the parser
// are transient and read the declaration when they are resolved.
func registerClientAssertion() {
	var r godi.Registry

	godi.AddSingleton[replay.Registry, lazyReplayRegistry](&r)

	godi.AddSingletonFactory[validators.ClientFeatureDeclarations](&r, func(p godi.Provider) validators.ClientFeatureDeclarations {
		return godi.GetRequired[*ServerConfig](p)
	})

	godi.AddSingletonFactory[*clientassertion.KeySource](&r, func(p godi.Provider) *clientassertion.KeySource {
		return clientassertion.NewKeySource(
			godi.GetRequired[*ServerConfig](p).PrivateKeyJwtOptions,
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})

	godi.AddTransientFactory[*clientassertion.Verifier](&r, func(p godi.Provider) *clientassertion.Verifier {
		return clientassertion.NewVerifier(
			godi.GetRequired[*ServerConfig](p).PrivateKeyJwtOptions,
			godi.GetRequired[*clientassertion.KeySource](p),
			godi.GetRequired[replay.Registry](p),
			godi.GetRequired[services.SystemClock](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})

	godi.AddTransientFactory[validators.SecretParser](&r, clientAssertionSecretParserFromProvider)
}
