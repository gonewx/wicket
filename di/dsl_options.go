// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"github.com/gonewx/godi"
	optspkg "github.com/gonewx/wicket/di/options"
)

func AddOptions[T optspkg.Entity[T]](r *godi.Registry) *godi.Registry {
	godi.AddSingleton[optspkg.Options[T], optspkg.UnnamedOptionsManager[T]](r)
	return godi.AddTransientFactory[optspkg.OptionsFactory[T]](r, func(p godi.Provider) optspkg.OptionsFactory[T] {
		return optspkg.NewOptionsFactory[T](
			godi.GetServices[optspkg.ConfigureOptions[T]](p),
			godi.GetServices[optspkg.PostConfigureOptions[T]](p),
			godi.GetServices[optspkg.ValidateOptions[T]](p),
		)
	})
}
