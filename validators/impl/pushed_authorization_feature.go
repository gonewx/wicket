// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// PushedAuthorizationFeature is implemented by feature declarations that can
// report whether pushed authorization requests (RFC 9126) are enabled.
type PushedAuthorizationFeature interface {
	// PushedAuthorizationRequestsEnabled reports whether pushed
	// authorization requests are declared enabled in this assembly.
	PushedAuthorizationRequestsEnabled() bool
}

func pushedAuthorizationRequestsEnabled(features validators.ClientFeatureDeclarations) bool {
	if features == nil {
		return false
	}
	declared, ok := features.(PushedAuthorizationFeature)
	return ok && declared.PushedAuthorizationRequestsEnabled()
}

// validatePushedAuthorizationMetadata returns the configuration error of a
// client's pushed authorization metadata, or "" when it is valid.
func validatePushedAuthorizationMetadata(features validators.ClientFeatureDeclarations, client *storage_models.Client) string {
	if client.RequestUriLifetime < 0 {
		return "client declares a negative request_uri lifetime"
	}
	if client.RequirePushedAuthorizationRequests && !pushedAuthorizationRequestsEnabled(features) {
		return "client requires pushed authorization requests but the feature is not enabled"
	}
	return ""
}
