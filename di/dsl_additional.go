// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/storage"
)

// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Additional.cs
// Static marker only; Epic 3.5 fills this registration block.
func registerAdditional() {
	var r godi.Registry
	// From: IdentityServer4/src/IdentityServer/Configuration/DependencyInjection/BuilderExtensions/Additional.cs
	// Dotnet leaves IAuthorizationParametersMessageStore absent by default; AddAuthorizationParametersMessageStore<T> explicitly adds it.
	godi.AddTransientFactory[storage.AuthorizationParametersMessageStore](&r, func(p godi.Provider) storage.AuthorizationParametersMessageStore {
		return godi.GetRequired[*ServerConfig](p).AuthorizationParametersMessageStore()
	})
	_ = r
}
