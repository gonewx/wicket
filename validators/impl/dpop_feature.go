// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// DPoPFeature is implemented by feature declarations that can report whether
// DPoP (RFC 9449) is enabled.
type DPoPFeature interface {
	// DPoPEnabled reports whether DPoP is declared enabled in this assembly.
	DPoPEnabled() bool
}

func dpopEnabled(features validators.ClientFeatureDeclarations) bool {
	if features == nil {
		return false
	}
	declared, ok := features.(DPoPFeature)
	return ok && declared.DPoPEnabled()
}

// validateDPoPMetadata returns the configuration error of a client that
// requires DPoP, or "" when it is valid or does not require it.
func validateDPoPMetadata(features validators.ClientFeatureDeclarations, client *storage_models.Client) string {
	if !client.RequireDPoP {
		return ""
	}
	if !dpopEnabled(features) {
		return "client requires DPoP but the feature is not enabled"
	}
	if client.AllowAccessTokensViaBrowser {
		// An access token issued over the front channel carries no proof and
		// could only be a bearer token.
		return "client requires DPoP but allows access tokens via the browser"
	}
	return ""
}
