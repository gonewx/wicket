// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"slices"

	"github.com/gonewx/wicket"
)

// highSecurityProfileAuthenticationMethods are the token endpoint
// authentication methods the high security profile accepts.
var highSecurityProfileAuthenticationMethods = []string{
	wicket.EndpointAuthenticationMethodsPrivateKeyJwt,
	wicket.EndpointAuthenticationMethodsTlsClientAuth,
	wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
}

// ServeHighSecurityProfile records that the assembly enforces the high
// security profile. The handler then narrows the settled document to what
// the profile allows, see settleHighSecurityProfileAdvertisement.
func (h *DiscoveryHandler) ServeHighSecurityProfile() {
	h.servesHighSecurityProfile = true
}

// settleHighSecurityProfileAdvertisement narrows the filtered document to the
// values the high security profile allows: S256 PKCE only, the asymmetric
// token endpoint authentication methods only, the code response type only,
// no password or implicit grant, and the iss authorization response
// parameter. It only removes values, except that the iss flag, which the
// profile turns on, is advertised as true. Host entries under names the
// generator does not write are left untouched, as by the other filters.
func settleHighSecurityProfileAdvertisement(filter *discoveryFilter) {
	filter.removeListValues(wicket.DiscoveryCodeChallengeMethodsSupported, func(value string) bool {
		return value != wicket.CodeChallengeMethodsSha256
	})
	filter.removeListValues(wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported, func(value string) bool {
		return !slices.Contains(highSecurityProfileAuthenticationMethods, value)
	})
	filter.removeListValues(wicket.DiscoveryResponseTypesSupported, func(value string) bool {
		return value != wicket.ResponseTypesCode
	})
	filter.removeListValues(wicket.DiscoveryGrantTypesSupported, func(value string) bool {
		return value == wicket.GrantTypePassword || value == wicket.GrantTypeImplicit
	})
	if _, ok := filter.document[wicket.DiscoveryAuthorizationResponseIssParameterSupported]; ok {
		filter.document[wicket.DiscoveryAuthorizationResponseIssParameterSupported] = true
	}
}
