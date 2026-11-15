// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"
	"slices"
	"strings"
	"time"

	config_options "github.com/gonewx/wicket/config/options"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

// The high security profile gathers the constraints of the FAPI 2.0
// Security Profile behind one switch. It does not rewrite the feature
// options the host declared on ServerConfig: those tightenings are folded
// into the effective value a getter returns ("declared or profile"), so the
// order in which the host calls the switches does not matter. Two
// WicketOptions fields are the exception: Freeze sets UseSeeOtherRedirects
// and EmitIssuerIdentificationResponseParameter to true on the bound
// options, overriding an explicit false of the host. Features that need host seams
// (pushed authorization, DPoP, private_key_jwt, mutual TLS) are not enabled
// by the profile; Freeze reports every missing one at once.

// highSecurityProfileSigningAlgorithms are the signature algorithms the
// profile accepts for client assertions and DPoP proofs.
var highSecurityProfileSigningAlgorithms = []string{"PS256", "ES256"}

// highSecurityProfileRequestUriLifetimeLimit is the pushed authorization
// request_uri lifetime the effective server lifetime must stay below.
const highSecurityProfileRequestUriLifetimeLimit = validators_impl.HighSecurityProfileRequestUriLifetimeLimit * time.Second

// EnableHighSecurityProfile declares the high security profile enabled. It
// must be called before Freeze. A repeated call has no further effect.
//
// While it is enabled, pushed authorization is required of every client,
// request objects need an asymmetric signature, the client_credentials grant
// needs client authentication, browser redirects use 303, the authorization
// response carries iss, and private_key_jwt assertions and DPoP proofs are
// accepted only with PS256 or ES256 among the configured algorithms. Freeze
// fails unless pushed authorization, a sender constraint (DPoP or mutual
// TLS) and an asymmetric client authentication (private_key_jwt or mutual
// TLS) are enabled, and fails for a client of the static list that conflicts
// with the profile; a client of an injected store that conflicts is treated
// as an invalid client on read.
func (c *ServerConfig) EnableHighSecurityProfile() {
	if c.frozen {
		panic("EnableHighSecurityProfile must not be called after Freeze")
	}
	c.highSecurityProfileEnabled = true
}

// HighSecurityProfileEnabled reports whether the high security profile was
// declared enabled.
func (c *ServerConfig) HighSecurityProfileEnabled() bool {
	return c != nil && c.highSecurityProfileEnabled
}

// highSecurityProfileAlgorithms returns those of the configured algorithms
// the profile accepts, in configuration order. The result stays empty when
// none is accepted; it is never replaced by a default.
func highSecurityProfileAlgorithms(configured []string) []string {
	accepted := make([]string, 0, len(configured))
	for _, algorithm := range configured {
		if slices.Contains(highSecurityProfileSigningAlgorithms, algorithm) && !slices.Contains(accepted, algorithm) {
			accepted = append(accepted, algorithm)
		}
	}
	return accepted
}

// bindHighSecurityProfileOptions records a materialized WicketOptions value
// so that Freeze can apply the profile to it. The options are materialized
// while the container is built, before the host can declare the profile.
func (c *ServerConfig) bindHighSecurityProfileOptions(options *config_options.WicketOptions) {
	if c == nil || options == nil {
		return
	}
	c.highSecurityProfileOptionsMu.Lock()
	defer c.highSecurityProfileOptionsMu.Unlock()
	if !slices.Contains(c.highSecurityProfileOptions, options) {
		c.highSecurityProfileOptions = append(c.highSecurityProfileOptions, options)
	}
	if c.HighSecurityProfileEnabled() {
		applyHighSecurityProfileOptions(options)
	}
}

// applyHighSecurityProfileOptions turns on the protocol options the profile
// requires: 303 redirects and the iss authorization response parameter.
func applyHighSecurityProfileOptions(options *config_options.WicketOptions) {
	options.UseSeeOtherRedirects = true
	options.EmitIssuerIdentificationResponseParameter = true
}

// applyHighSecurityProfileToOptions applies the enabled profile to every
// bound WicketOptions value.
func (c *ServerConfig) applyHighSecurityProfileToOptions() {
	if !c.HighSecurityProfileEnabled() {
		return
	}
	c.highSecurityProfileOptionsMu.Lock()
	defer c.highSecurityProfileOptionsMu.Unlock()
	for _, options := range c.highSecurityProfileOptions {
		applyHighSecurityProfileOptions(options)
	}
}

// highSecurityProfileDeficiencies lists every prerequisite the enabled
// profile misses and every conflict of a client of the static list.
func (c *ServerConfig) highSecurityProfileDeficiencies() []string {
	if !c.HighSecurityProfileEnabled() {
		return nil
	}
	var missing []string
	if !c.PushedAuthorizationRequestsEnabled() {
		missing = append(missing, "pushed authorization requests are not enabled")
	} else if lifetime := c.PushedAuthorizationRequestsOptions().RequestUriLifetime; lifetime >= highSecurityProfileRequestUriLifetimeLimit {
		missing = append(missing, fmt.Sprintf("the pushed authorization request_uri lifetime %s is not below %s", lifetime, highSecurityProfileRequestUriLifetimeLimit))
	}
	if !c.DPoPEnabled() && !c.ClientCertificateAuthenticationEnabled() {
		missing = append(missing, "no sender constraint is enabled: enable DPoP or mutual TLS client authentication")
	}
	if !c.PrivateKeyJwtEnabled() && !c.ClientCertificateAuthenticationEnabled() {
		missing = append(missing, "no asymmetric client authentication is enabled: enable private_key_jwt or mutual TLS client authentication")
	}
	if c.PrivateKeyJwtEnabled() && len(c.PrivateKeyJwtOptions().SigningAlgorithms) == 0 {
		missing = append(missing, "private_key_jwt accepts neither PS256 nor ES256")
	}
	if c.DPoPEnabled() && len(c.DPoPOptions().SigningAlgorithms) == 0 {
		missing = append(missing, "DPoP accepts neither PS256 nor ES256")
	}
	for _, client := range c.Clients() {
		if client == nil {
			continue
		}
		if conflicts := validators_impl.HighSecurityProfileConflicts(client); len(conflicts) > 0 {
			missing = append(missing, fmt.Sprintf("client %q conflicts with the profile: %s", client.ClientId, strings.Join(conflicts, "; ")))
		}
	}
	return missing
}

// requireHighSecurityProfile panics with every deficiency of the enabled
// profile at once, and applies the profile to the bound options otherwise.
func (c *ServerConfig) requireHighSecurityProfile() {
	if missing := c.highSecurityProfileDeficiencies(); len(missing) > 0 {
		panic("high security profile cannot be served: " + strings.Join(missing, "; "))
	}
	c.applyHighSecurityProfileToOptions()
}
