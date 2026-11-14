// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
)

// settleMutualTlsAdvertisement adjusts the filtered document of an assembly
// that serves mutual TLS client authentication:
//   - while mutual TLS is not advertised (MutualTls.Enabled off), the tls
//     methods the registered parsers list are withdrawn;
//   - the authentication methods list is deduplicated, keeping the first
//     occurrence of each method, since the generator appends the tls methods
//     after those of the parsers;
//   - certificate bound access tokens are not advertised, as nothing issues
//     them yet.
//
// These withdrawals are expected and are not logged.
func settleMutualTlsAdvertisement(document map[string]any, options *config_options.WicketOptions) {
	advertised := options != nil && options.MutualTls != nil && options.MutualTls.Enabled
	key := wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported
	keep := func(method string, seen map[string]struct{}) bool {
		if !advertised && isTlsAuthenticationMethod(method) {
			return false
		}
		if _, ok := seen[method]; ok {
			return false
		}
		seen[method] = struct{}{}
		return true
	}
	switch values := document[key].(type) {
	case []string:
		seen := map[string]struct{}{}
		kept := make([]string, 0, len(values))
		for _, method := range values {
			if keep(method, seen) {
				kept = append(kept, method)
			}
		}
		document[key] = kept
	case []any:
		seen := map[string]struct{}{}
		kept := make([]any, 0, len(values))
		for _, value := range values {
			method, ok := value.(string)
			if !ok {
				kept = append(kept, value)
				continue
			}
			if keep(method, seen) {
				kept = append(kept, value)
			}
		}
		document[key] = kept
	}
	delete(document, wicket.DiscoveryTlsClientCertificateBoundAccessTokens)
}
