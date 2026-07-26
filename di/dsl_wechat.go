// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/wechatverify"
)

// registerWeChatVerify registers the configuration extension point only. The
// Verifier itself is not registered: it refuses construction without
// credentials, so a container-built instance from an empty configuration would
// fail. Consumers supply a populated configuration and build the verifier in
// their own composition root.
//
// The registered configuration is a single shared pointer handed to every
// scope. It is a startup-time extension point: populate it while the container
// is being assembled, before any scope is served. Writing to it once requests
// are in flight races every reader, and blanking a credential at that point
// turns the next construction into ErrUnavailable — closing the capability with
// no failure anywhere to explain it.
func registerWeChatVerify() {
	var r godi.Registry

	godi.AddSingletonFactory[*wechatverify.Config](&r, func(p godi.Provider) *wechatverify.Config {
		return &wechatverify.Config{}
	})
}
