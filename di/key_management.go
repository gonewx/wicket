// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

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
// consumers that resolve it. Unlike the host store seams in registerCrypto, the
// factory reads only singleton options and the data protection provider; it does
// not read the ServerConfig store seam, so eager singleton assembly does not
// freeze that seam prematurely.
func registerKeyManagement() {
	var r godi.Registry

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

		store := opts.StorageProvider
		if store == nil {
			store = keymgmt.NewMemoryRecordStore()
		}

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

// resolveAutoCreate maps the tri-state AutoCreate option: unset defaults to on so
// an enabled manager bootstraps a key; an explicit value is honoured.
func resolveAutoCreate(opts *config_options.KeyManagementOptions) bool {
	if opts.AutoCreate == nil {
		return true
	}
	return *opts.AutoCreate
}
