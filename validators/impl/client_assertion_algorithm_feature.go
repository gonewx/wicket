// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"slices"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// ClientAssertionAlgorithmFeature is implemented by feature declarations
// that can report the signature algorithms the server accepts for
// private_key_jwt client assertions.
type ClientAssertionAlgorithmFeature interface {
	// PrivateKeyJwtSigningAlgorithms returns the algorithms the server
	// accepts for private_key_jwt, or nil while the feature is not enabled.
	PrivateKeyJwtSigningAlgorithms() []string
}

func privateKeyJwtSigningAlgorithms(features validators.ClientFeatureDeclarations) []string {
	if features == nil {
		return nil
	}
	declared, ok := features.(ClientAssertionAlgorithmFeature)
	if !ok {
		return nil
	}
	return declared.PrivateKeyJwtSigningAlgorithms()
}

// validateTokenEndpointAuthSigningAlgorithms returns the configuration error
// of a client whose assertion algorithm list is not usable, or "" when the
// list is empty or valid.
func validateTokenEndpointAuthSigningAlgorithms(features validators.ClientFeatureDeclarations, client *storage_models.Client) string {
	if len(client.TokenEndpointAuthSigningAlgorithms) == 0 {
		return ""
	}
	if client.TokenEndpointAuthMethod != wicket.EndpointAuthenticationMethodsPrivateKeyJwt {
		return "client lists token endpoint authentication signing algorithms but does not use private_key_jwt"
	}
	accepted := privateKeyJwtSigningAlgorithms(features)
	for _, algorithm := range client.TokenEndpointAuthSigningAlgorithms {
		if algorithm == "" || !slices.Contains(accepted, algorithm) {
			return "client lists a token endpoint authentication signing algorithm the server does not accept for private_key_jwt"
		}
	}
	return ""
}
