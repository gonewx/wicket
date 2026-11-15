// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"log/slog"
	"slices"

	"github.com/gonewx/wicket"
)

// ServeAccountCreation records that the assembly serves the create prompt
// from a host account creation page. The handler then advertises the
// supported prompt values, see settlePromptValuesAdvertisement.
func (h *DiscoveryHandler) ServeAccountCreation() {
	h.servesAccountCreation = true
}

// settlePromptValuesAdvertisement writes prompt_values_supported. The key is
// written only here: a value already in the document, which can only come
// from the host's custom entries, is dropped with a warning. The supported
// prompt values, create included, are written while account creation is
// served and the authorization endpoint is advertised.
func settlePromptValuesAdvertisement(document map[string]any, served bool, logger *slog.Logger) {
	key := wicket.DiscoveryPromptValuesSupported
	if _, ok := document[key]; ok {
		delete(document, key)
		if logger != nil {
			logger.Warn("A custom discovery entry named prompt_values_supported is ignored; the key is written only from the account creation declaration.")
		}
	}
	if !served {
		return
	}
	if _, ok := document[wicket.DiscoveryAuthorizationEndpoint]; !ok {
		return
	}
	document[key] = append(slices.Clone(wicket.SupportedPromptModes), wicket.PromptModesCreate)
}
