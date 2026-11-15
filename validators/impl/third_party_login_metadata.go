// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	storage_models "github.com/gonewx/wicket/storage/models"
)

// validateThirdPartyLoginMetadata returns the configuration error of a client
// whose registered login initiation endpoint is not an absolute https URI, or
// "" when it is valid or none is registered. The rule applies regardless of
// the features the assembly enables.
func validateThirdPartyLoginMetadata(client *storage_models.Client) string {
	if client.InitiateLoginUri == "" {
		return ""
	}
	if !storage_models.IsAbsoluteHttpsUri(client.InitiateLoginUri) {
		return "client registers an initiate_login_uri that is not an absolute https URI"
	}
	return ""
}
