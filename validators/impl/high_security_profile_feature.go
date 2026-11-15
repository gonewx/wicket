// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"net/url"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// HighSecurityProfileFeature is implemented by feature declarations that can
// report whether the high security profile is enabled.
type HighSecurityProfileFeature interface {
	// HighSecurityProfileEnabled reports whether the high security profile
	// is declared enabled in this assembly.
	HighSecurityProfileEnabled() bool
}

// Limits of the high security profile on client metadata.
const (
	// HighSecurityProfileMaxAuthorizationCodeLifetime is the longest
	// authorization code lifetime, in seconds, a client may declare.
	HighSecurityProfileMaxAuthorizationCodeLifetime = 60
	// HighSecurityProfileRequestUriLifetimeLimit is the request_uri lifetime,
	// in seconds, a client must stay below.
	HighSecurityProfileRequestUriLifetimeLimit = 600
)

func highSecurityProfileEnabled(features validators.ClientFeatureDeclarations) bool {
	if features == nil {
		return false
	}
	declared, ok := features.(HighSecurityProfileFeature)
	return ok && declared.HighSecurityProfileEnabled()
}

// highSecurityProfileForbiddenGrantTypes are the grant types a client may not
// be allowed under the high security profile.
var highSecurityProfileForbiddenGrantTypes = []string{
	wicket.GrantTypePassword,
	wicket.GrantTypeImplicit,
	wicket.GrantTypeHybrid,
}

// HighSecurityProfileConflicts lists every item of the client's configuration
// that conflicts with the high security profile, in a fixed order, or nil
// when it complies. It does not look at whether the profile is enabled.
func HighSecurityProfileConflicts(client *storage_models.Client) []string {
	if client == nil {
		return nil
	}
	var conflicts []string
	switch client.TokenEndpointAuthMethod {
	case wicket.EndpointAuthenticationMethodsPrivateKeyJwt,
		wicket.EndpointAuthenticationMethodsTlsClientAuth,
		wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth:
	default:
		conflicts = append(conflicts, "token endpoint authentication method is not private_key_jwt, tls_client_auth or self_signed_tls_client_auth")
	}
	if !client.RequireDPoP && !client.TlsClientCertificateBoundAccessTokens {
		conflicts = append(conflicts, "neither DPoP nor certificate bound access tokens are required")
	}
	if !client.RequirePkce {
		conflicts = append(conflicts, "PKCE is not required")
	}
	if client.AllowPlainTextPkce {
		conflicts = append(conflicts, "plain PKCE is allowed")
	}
	for _, grantType := range highSecurityProfileForbiddenGrantTypes {
		if slices.Contains(client.AllowedGrantTypes(), grantType) {
			conflicts = append(conflicts, "grant type "+grantType+" is allowed")
		}
	}
	if client.AuthorizationCodeLifetime > HighSecurityProfileMaxAuthorizationCodeLifetime {
		conflicts = append(conflicts, "authorization code lifetime exceeds 60 seconds")
	}
	if client.RequestUriLifetime >= HighSecurityProfileRequestUriLifetimeLimit {
		conflicts = append(conflicts, "request_uri lifetime is not below 600 seconds")
	}
	for _, redirectUri := range client.RedirectUris {
		if isNonLoopbackHttpUri(redirectUri) {
			conflicts = append(conflicts, "redirect URI uses http without a loopback IP literal host")
			break
		}
	}
	return conflicts
}

// isNonLoopbackHttpUri reports whether raw uses the http scheme with a host
// other than the loopback IP literals 127.0.0.1 and [::1]. A URI that does not
// parse is judged by its scheme prefix alone.
func isNonLoopbackHttpUri(raw string) bool {
	if !strings.HasPrefix(strings.ToLower(raw), "http:") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return true
	}
	// url.Parse refuses an unbracketed "::1" host, so a parsed "::1" is
	// always the bracketed loopback literal.
	host := parsed.Hostname()
	return host != "127.0.0.1" && host != "::1"
}

// HighSecurityProfileSigningAlgorithmConflict returns the configuration
// error of a client whose token endpoint authentication signing algorithms
// the server does not accept, or "" when they are acceptable. It applies the
// same rule as the default ClientConfigurationValidator, so that assembly can
// report a client of the static list whose algorithms fall outside the set
// the high security profile narrows the server to.
func HighSecurityProfileSigningAlgorithmConflict(features validators.ClientFeatureDeclarations, client *storage_models.Client) string {
	if client == nil {
		return ""
	}
	return validateTokenEndpointAuthSigningAlgorithms(features, client)
}

// validateHighSecurityProfile returns the configuration error of a client
// that conflicts with the enabled high security profile, or "" when the
// profile is not enabled or the client complies.
func validateHighSecurityProfile(features validators.ClientFeatureDeclarations, client *storage_models.Client) string {
	if !highSecurityProfileEnabled(features) {
		return ""
	}
	conflicts := HighSecurityProfileConflicts(client)
	if len(conflicts) == 0 {
		return ""
	}
	return "client conflicts with the high security profile: " + strings.Join(conflicts, "; ")
}
