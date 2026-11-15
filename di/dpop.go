// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"slices"

	"github.com/gonewx/wicket/dpop"
)

// dpopFeatureName is the replay dependent feature name of DPoP. The entry
// recorded under this name is the only enablement state of the feature.
const dpopFeatureName = "dpop"

// EnableDPoP declares DPoP (RFC 9449) enabled at the token endpoint with the
// given options. It must be called before Freeze. A repeated call replaces
// the options. Once enabled, the replay registry seam is required.
func (c *ServerConfig) EnableDPoP(options dpop.Options) {
	if c.frozen {
		panic("EnableDPoP must not be called after Freeze")
	}
	options.SigningAlgorithms = slices.Clone(options.SigningAlgorithms)
	c.dpopOptions = options
	c.enableReplayDependentFeature(dpopFeatureName)
}

// DPoPEnabled reports whether DPoP was declared enabled.
func (c *ServerConfig) DPoPEnabled() bool {
	return c.replayDependentFeatureEnabled(dpopFeatureName)
}

// DPoPOptions returns a copy of the declared options with every unset field
// replaced by its default. It returns the zero value while DPoP is not
// enabled.
func (c *ServerConfig) DPoPOptions() dpop.Options {
	if !c.DPoPEnabled() {
		return dpop.Options{}
	}
	options := c.dpopOptions
	defaults := dpop.DefaultOptions()
	if len(options.SigningAlgorithms) == 0 {
		options.SigningAlgorithms = defaults.SigningAlgorithms
	} else {
		options.SigningAlgorithms = slices.Clone(options.SigningAlgorithms)
	}
	if options.ProofLifetime == 0 {
		options.ProofLifetime = defaults.ProofLifetime
	}
	if options.ClockSkew == 0 {
		options.ClockSkew = defaults.ClockSkew
	}
	return options
}

// requireDPoPOptions panics when DPoP is enabled with options that do not
// validate.
func (c *ServerConfig) requireDPoPOptions() {
	if !c.DPoPEnabled() {
		return
	}
	if err := c.DPoPOptions().Validate(); err != nil {
		panic("dpop options invalid: " + err.Error())
	}
}
