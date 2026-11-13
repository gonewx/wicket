// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/tokens"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type DiscoveryResponseGenerator struct {
	// The options
	options *config_options.WicketOptions

	// The extension grants validator
	extensionGrants *validators_impl.ExtensionGrantValidator

	// The key material service
	keys services.KeyMaterialService

	// The resource owner validator
	resourceOwnerValidator validators.ResourceOwnerPasswordValidator

	// The resource store
	resourceStore storage.ResourceStore

	// The secret parsers
	secretParsers validators.SecretsListParser

	// The logger
	logger *slog.Logger
}

func NewDiscoveryResponseGenerator(
	options *config_options.WicketOptions,
	extensionGrants *validators_impl.ExtensionGrantValidator,
	keys services.KeyMaterialService,
	resourceOwnerValidator validators.ResourceOwnerPasswordValidator,
	resourceStore storage.ResourceStore,
	secretParsers validators.SecretsListParser,
	logger *slog.Logger,
) *DiscoveryResponseGenerator {
	return &DiscoveryResponseGenerator{
		options:                options,
		extensionGrants:        extensionGrants,
		keys:                   keys,
		resourceOwnerValidator: resourceOwnerValidator,
		resourceStore:          resourceStore,
		secretParsers:          secretParsers,
		logger:                 logger,
	}
}

func (g *DiscoveryResponseGenerator) constructMtlsEndpoint(baseUrl string, issuerUri string, endpoint string) string {
	// path based
	if g.options.MutualTls.DomainName == "" {
		return baseUrl + strings.Replace(endpoint, wicket.ProtocolRoutePathsConnectPathPrefix, wicket.ProtocolRoutePathsMtlsPathPrefix, -1)
	}

	// domain based
	if strings.Contains(g.options.MutualTls.DomainName, ".") {
		return fmt.Sprintf("https://%s/%s", g.options.MutualTls.DomainName, endpoint)
	} else {
		// sub-domain based
		parts := strings.Split(baseUrl, "://")
		return fmt.Sprintf("https://%s.%s%s", g.options.MutualTls.DomainName, parts[1], endpoint)
	}
}

// CreateDiscoveryDocument Creates the discovery document.
func (g *DiscoveryResponseGenerator) CreateDiscoveryDocument(ctx context.Context, baseUrl string, issuerUri string) (map[string]any, error) {
	baseUrl = utils.RemoveTrailingSlash(baseUrl)
	joinUrl := func(path string) string { return baseUrl + "/" + strings.TrimLeft(path, "/") }

	entries := make(map[string]any, 0)
	entries[wicket.DiscoveryIssuer] = issuerUri

	// jwks
	if g.options.Discovery.ShowKeySet {
		keys, err := g.keys.GetValidationKeys(ctx)
		if err != nil {
			return nil, err
		}

		if len(keys) > 0 {
			entries[wicket.DiscoveryJwksUri] = joinUrl(wicket.ProtocolRoutePathsDiscoveryWebKeys)
		}
	}

	// endpoints
	if g.options.Discovery.ShowEndpoints {
		if g.options.Endpoints.EnableAuthorizeEndpoint {
			entries[wicket.DiscoveryAuthorizationEndpoint] = joinUrl(wicket.ProtocolRoutePathsAuthorize)
		}

		if g.options.Endpoints.EnableTokenEndpoint {
			entries[wicket.DiscoveryTokenEndpoint] = joinUrl(wicket.ProtocolRoutePathsToken)
		}

		if g.options.Endpoints.EnableUserInfoEndpoint {
			entries[wicket.DiscoveryUserInfoEndpoint] = joinUrl(wicket.ProtocolRoutePathsUserInfo)
		}

		if g.options.Endpoints.EnableEndSessionEndpoint {
			entries[wicket.DiscoveryEndSessionEndpoint] = joinUrl(wicket.ProtocolRoutePathsEndSession)
		}

		if g.options.Endpoints.EnableCheckSessionEndpoint {
			entries[wicket.DiscoveryCheckSessionIframe] = joinUrl(wicket.ProtocolRoutePathsCheckSession)
		}

		if g.options.Endpoints.EnableTokenRevocationEndpoint {
			entries[wicket.DiscoveryRevocationEndpoint] = joinUrl(wicket.ProtocolRoutePathsRevocation)
		}

		if g.options.Endpoints.EnableIntrospectionEndpoint {
			entries[wicket.DiscoveryIntrospectionEndpoint] = joinUrl(wicket.ProtocolRoutePathsIntrospection)
		}

		if g.options.Endpoints.EnableDeviceAuthorizationEndpoint {
			entries[wicket.DiscoveryDeviceAuthorizationEndpoint] = joinUrl(wicket.ProtocolRoutePathsDeviceAuthorization)
		}

		if g.options.Endpoints.EnableBackchannelAuthenticationEndpoint {
			entries[wicket.DiscoveryBackchannelAuthenticationEndpoint] = joinUrl(wicket.ProtocolRoutePathsBackchannelAuthentication)
		}

		if g.options.MutualTls.Enabled {
			mtlsEndpoints := make(map[string]string, 0)

			if g.options.Endpoints.EnableTokenEndpoint {
				mtlsEndpoints[wicket.DiscoveryTokenEndpoint] = g.constructMtlsEndpoint(baseUrl, issuerUri, wicket.ProtocolRoutePathsToken)
			}
			if g.options.Endpoints.EnableTokenRevocationEndpoint {
				mtlsEndpoints[wicket.DiscoveryRevocationEndpoint] = g.constructMtlsEndpoint(baseUrl, issuerUri, wicket.ProtocolRoutePathsRevocation)
			}
			if g.options.Endpoints.EnableIntrospectionEndpoint {
				mtlsEndpoints[wicket.DiscoveryIntrospectionEndpoint] = g.constructMtlsEndpoint(baseUrl, issuerUri, wicket.ProtocolRoutePathsIntrospection)
			}
			if g.options.Endpoints.EnableDeviceAuthorizationEndpoint {
				mtlsEndpoints[wicket.DiscoveryDeviceAuthorizationEndpoint] = g.constructMtlsEndpoint(baseUrl, issuerUri, wicket.ProtocolRoutePathsDeviceAuthorization)
			}

			if len(mtlsEndpoints) > 0 {
				entries[wicket.DiscoveryMtlsEndpointAliases] = mtlsEndpoints
			}

		}
	}

	// logout
	if g.options.Endpoints.EnableEndSessionEndpoint {
		entries[wicket.DiscoveryFrontChannelLogoutSupported] = true
		entries[wicket.DiscoveryFrontChannelLogoutSessionSupported] = true
		entries[wicket.DiscoveryBackchannelLogoutSupported] = true
		entries[wicket.DiscoveryBackchannelLogoutSessionSupported] = true
	}

	// scopes and claims.
	if g.options.Discovery.ShowIdentityScopes ||
		g.options.Discovery.ShowApiScopes ||
		g.options.Discovery.ShowClaims {
		resources, err := g.resourceStore.GetAllEnabledResources(ctx)
		if err != nil {
			return nil, err
		}

		var scopes []string

		// scopes
		if g.options.Discovery.ShowIdentityScopes {
			scopes = append(scopes,
				utils.Select(
					utils.Where(resources.IdentityResources(),
						func(x *storage_models.IdentityResource) bool { return x.ShowInDiscoveryDocument },
					),
					func(x *storage_models.IdentityResource) string { return x.Name },
				)...,
			)

		}

		if g.options.Discovery.ShowApiScopes {
			apiScopes := utils.Select(
				utils.Where(resources.ApiScopes(), func(x *storage_models.ApiScope) bool {
					return x.ShowInDiscoveryDocument
				}), func(x *storage_models.ApiScope) string {
					return x.Name
				})

			scopes = append(scopes, apiScopes...)
			scopes = append(scopes, wicket.StandardScopesOfflineAccess)
		}

		if len(scopes) > 0 {
			entries[wicket.DiscoveryScopesSupported] = scopes
		}

		// claims.
		if g.options.Discovery.ShowClaims {
			claims := make([]string, 0)

			// add non-hidden identity scopes related claims.
			claims = append(claims, utils.SelectMany(
				utils.Where(resources.IdentityResources(), func(x *storage_models.IdentityResource) bool {
					return x.ShowInDiscoveryDocument
				}), func(x *storage_models.IdentityResource) []string {
					return x.UserClaims
				})...)

			claims = append(claims, utils.SelectMany(
				utils.Where(resources.ApiResources(), func(x *storage_models.ApiResource) bool {
					return x.ShowInDiscoveryDocument
				}), func(x *storage_models.ApiResource) []string {
					return x.UserClaims
				})...)

			claims = append(claims, utils.SelectMany(
				utils.Where(resources.ApiScopes(), func(x *storage_models.ApiScope) bool {
					return x.ShowInDiscoveryDocument
				}), func(x *storage_models.ApiScope) []string {
					return x.UserClaims
				})...)

			entries[wicket.DiscoveryClaimsSupported] = utils.Distinct(claims)
		}
	}

	// grant types
	if g.options.Discovery.ShowGrantTypes {
		standardGrantTypes := []string{
			wicket.GrantTypeAuthorizationCode,
			wicket.GrantTypeClientCredentials,
			wicket.GrantTypeRefreshToken,
			wicket.GrantTypeImplicit,
		}

		if _, ok := g.resourceOwnerValidator.(*validators_impl.NotSupportedResourceOwnerPasswordValidator); !ok {
			standardGrantTypes = append(standardGrantTypes, wicket.GrantTypePassword)
		}

		if g.options.Endpoints.EnableDeviceAuthorizationEndpoint {
			standardGrantTypes = append(standardGrantTypes, wicket.GrantTypeDeviceCode)
		}

		if g.options.Endpoints.EnableBackchannelAuthenticationEndpoint {
			standardGrantTypes = append(standardGrantTypes, wicket.GrantTypeBackchannelAuthentication)
		}

		if g.options.Discovery.ShowExtensionGrantTypes {
			standardGrantTypes = append(standardGrantTypes, g.extensionGrants.GetAvailableGrantTypes()...)
		}

		entries[wicket.DiscoveryGrantTypesSupported] = standardGrantTypes

	}

	// response types
	if g.options.Discovery.ShowResponseTypes {
		entries[wicket.DiscoveryResponseTypesSupported] = wicket.SupportedResponseTypes
	}

	// response modes
	if g.options.Discovery.ShowResponseModes {
		entries[wicket.DiscoveryResponseModesSupported] = wicket.SupportedResponseModes
	}

	// misc
	if g.options.Discovery.ShowTokenEndpointAuthenticationMethods {
		types := g.secretParsers.GetAvailableAuthenticationMethods()
		if g.options.MutualTls.Enabled {
			types = append(types, wicket.EndpointAuthenticationMethodsTlsClientAuth)
			types = append(types, wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth)
		}

		entries[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported] = types
	}

	signingCredentials, err := g.keys.GetAllSigningCredentials(ctx)
	if err != nil {
		return nil, err
	}

	if len(signingCredentials) > 0 {
		signingAlgorithms := utils.Distinct(
			utils.Select(signingCredentials, func(x *tokens.SigningCredentials) string {
				return x.Algorithm
			}))
		entries[wicket.DiscoveryIdTokenSigningAlgorithmsSupported] = signingAlgorithms
	}

	entries[wicket.DiscoverySubjectTypesSupported] = []string{"public"}
	entries[wicket.DiscoveryCodeChallengeMethodsSupported] = []string{wicket.CodeChallengeMethodsPlain, wicket.CodeChallengeMethodsSha256}

	if g.options.Endpoints.EnableAuthorizeEndpoint {
		entries[wicket.DiscoveryRequestParameterSupported] = true

		entries[wicket.DiscoveryRequestObjectSigningAlgorithmsSupported] = []string{
			wicket.SecurityAlgorithmsRsaSha256,
			wicket.SecurityAlgorithmsRsaSha384,
			wicket.SecurityAlgorithmsRsaSha512,
			wicket.SecurityAlgorithmsRsaSsaPssSha256,
			wicket.SecurityAlgorithmsRsaSsaPssSha384,
			wicket.SecurityAlgorithmsRsaSsaPssSha512,
			wicket.SecurityAlgorithmsEcdsaSha256,
			wicket.SecurityAlgorithmsEcdsaSha384,
			wicket.SecurityAlgorithmsEcdsaSha512,
			wicket.SecurityAlgorithmsHmacSha256,
			wicket.SecurityAlgorithmsHmacSha384,
			wicket.SecurityAlgorithmsHmacSha512,
		}

		if g.options.Endpoints.EnableJwtRequestUri {
			entries[wicket.DiscoveryRequestUriParameterSupported] = true
		}
	}

	entries[wicket.DiscoveryAuthorizationResponseIssParameterSupported] = true

	if g.options.MutualTls.Enabled {
		entries[wicket.DiscoveryTlsClientCertificateBoundAccessTokens] = true
	}

	if g.options.Endpoints.EnableBackchannelAuthenticationEndpoint {
		entries[wicket.DiscoveryBackchannelTokenDeliveryModesSupported] =
			g.options.BackchannelAuthentication.AllowedDeliveryModes
		entries[wicket.DiscoveryBackchannelUserCodeParameterSupported] = g.options.BackchannelAuthentication.UserCodeParameterSupported
	}

	// custom entries
	if len(g.options.Discovery.CustomEntries) > 0 {

		for key, value := range g.options.Discovery.CustomEntries {
			if _, ok := entries[key]; ok {
				g.logger.Error("Discovery custom entry cannot be added, because it already exists.", slog.String("key", key))
			} else {

				if customValueString, ok := value.(string); ok {
					if strings.HasPrefix(customValueString, "~/") && g.options.Discovery.ExpandRelativePathsInCustomEntries {
						entries[key] = joinUrl(strings.TrimPrefix(customValueString, "~/"))
						continue
					}
				}

				entries[key] = value
			}
		}
	}
	return entries, nil
}

// Creates the JWK document.
func (g *DiscoveryResponseGenerator) CreateJwkDocument(ctx context.Context) ([]*models.JsonWebKey, error) {

	webKeys := make([]*models.JsonWebKey, 0)
	validationKeys, err := g.keys.GetValidationKeys(ctx)
	if err != nil {
		return nil, err
	}

	for _, key := range validationKeys {
		k, err := jwk.Import(key.Key)
		if err != nil {
			return nil, err
		}
		if key.KeyId == "" || k.Set(jwk.KeyIDKey, key.KeyId) != nil {
			// No stable kid, or it could not be applied: derive one so no key is
			// ever published without a kid the token header can reference.
			_ = jwk.AssignKeyID(k)
		}
		_ = k.Set(jwk.AlgorithmKey, key.SigningAlgorithm)
		webKeys = append(webKeys, &models.JsonWebKey{Key: k})
	}

	return webKeys, nil
}
