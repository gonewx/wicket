// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"log/slog"
	"slices"

	"github.com/gonewx/wicket"
)

// ServeDPoP records that the assembly accepts DPoP proofs (RFC 9449) signed
// with the given algorithms. The handler then advertises them under
// dpop_signing_alg_values_supported, see settleDPoPAdvertisement.
func (h *DiscoveryHandler) ServeDPoP(algorithms []string) {
	h.dpopSigningAlgorithms = slices.Clone(algorithms)
	h.servesDPoP = true
}

// settleDPoPAdvertisement writes dpop_signing_alg_values_supported. The key
// is written only here: a value already in the document, which can only come
// from the host's custom entries, is dropped with a warning, and the
// configured algorithms are written while DPoP is served.
func settleDPoPAdvertisement(document map[string]any, served bool, algorithms []string, logger *slog.Logger) {
	key := wicket.DiscoveryDPoPSigningAlgValuesSupported
	if _, ok := document[key]; ok {
		delete(document, key)
		if logger != nil {
			logger.Warn("A custom discovery entry named dpop_signing_alg_values_supported is ignored; the key is written only from the DPoP declaration.")
		}
	}
	if served && len(algorithms) > 0 {
		document[key] = slices.Clone(algorithms)
	}
}
