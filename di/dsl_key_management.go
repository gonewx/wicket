// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"crypto/rand"
	"log/slog"

	"github.com/gonewx/godi"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/services"
)

// registerKeyManagement wires the automatic key manager. It is registered as a
// singleton so its in-memory key state and cache persist across the transient
// consumers that resolve it. The key record store comes from the ServerConfig
// seam through a lazy wrapper, so eager singleton assembly does not freeze the
// host seam prematurely; a host that injects a store adapter via the seam gets
// it, anything else falls back to the in-memory record store with a warning.
func registerKeyManagement() {
	var r godi.Registry

	godi.AddSingleton[keymgmt.RecordStore, lazyRecordStore](&r)

	godi.AddSingletonFactory[*keymgmt.Manager](&r, func(p godi.Provider) *keymgmt.Manager {
		opts := godi.GetRequired[*config_options.KeyManagementOptions](p)

		// TokenLifetimeCeiling stays unset here: token lifetimes are per-client
		// runtime data, so no ceiling is visible at composition time. A host
		// constructing the manager directly may supply one to arm the retention
		// adequacy warning.
		cfg := keymgmt.Config{
			Enabled:             opts.Enabled,
			AutoCreate:          resolveAutoCreate(opts),
			RotationInterval:    opts.RotationInterval,
			ActivationLeadTime:  opts.ActivationLeadTime,
			RetentionDuration:   opts.RetentionDuration,
			AllowedAlgorithms:   opts.AllowedAlgorithms,
			DefaultAlgorithm:    opts.DefaultAlgorithm,
			CacheTTL:            opts.CacheTTL,
			ClockSkew:           opts.ClockSkew,
			AllowMultipleActive: opts.AllowMultipleActive,
		}

		store := godi.GetRequired[keymgmt.RecordStore](p)

		var provider dp.DataProtectionProvider = opts.Protector
		if provider == nil {
			provider = godi.GetRequired[dp.DataProtectionProvider](p)
		}

		var clock keymgmt.Clock = opts.Clock
		if clock == nil {
			clock = godi.GetRequired[services.SystemClock](p)
		}

		var entropy keymgmt.Entropy = opts.Entropy
		if entropy == nil {
			entropy = rand.Reader
		}

		return keymgmt.NewManager(cfg, store, provider, clock, entropy, godi.GetRequired[*slog.Logger](p))
	})
}
