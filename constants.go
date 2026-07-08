// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package gois

import (
	"errors"
	"time"
)

const (
	WicketName                         = "wicket"
	LocalIdentityProvider              = "local"
	DefaultCookieAuthenticationScheme  = "wicket"
	SignoutScheme                      = "wicket"
	ExternalCookieAuthenticationScheme = "wicket.external"
	OpenIdConnectAuthenticationScheme  = "OpenIdConnect"
	GoogleAuthenticationScheme         = "Google"
	FacebookAuthenticationScheme       = "Facebook"
	JwtBearerAuthenticationScheme      = "Bearer"
	AccessTokenAudience                = "%sresources"
	DefaultCheckSessionCookieName      = "wicket.session"

	ExternalAuthenticationMethod = "external"
)

const (
	DefaultCookieTimeSpan = 10 * time.Hour
	DefaultCacheDuration  = 60 * time.Minute
)

var (
	WicketAuthenticationType = WicketName
)

type ResponseTypes string

const (
	ResponseTypesCode             = "code"
	ResponseTypesToken            = "token"
	ResponseTypesIdToken          = "id_token"
	ResponseTypesIdTokenToken     = "id_token token"
	ResponseTypesCodeIdToken      = "code id_token"
	ResponseTypesCodeToken        = "code token"
	ResponseTypesCodeIdTokenToken = "code id_token token"
)

const (
	GrantTypePassword                  = "password"
	GrantTypeHybrid                    = "hybrid"
	GrantTypeAuthorizationCode         = "authorization_code"
	GrantTypeClientCredentials         = "client_credentials"
	GrantTypeRefreshToken              = "refresh_token"
	GrantTypeImplicit                  = "implicit"
	GrantTypeSaml2Bearer               = "urn:ietf:params:oauth:grant-type:saml2-bearer"
	GrantTypeJwtBearer                 = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantTypeDeviceCode                = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTypeTokenExchange             = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantTypeBackchannelAuthentication = "urn:openid:params:grant-type:ciba"
)

const (
	ResponseModesFormPost = "form_post"
	ResponseModesQuery    = "query"
	ResponseModesFragment = "fragment"
)

const (
	CodeChallengeMethodsPlain  = "plain"
	CodeChallengeMethodsSha256 = "S256"
)

const (
	ProtocolTypesOpenIdConnect = "oidc"
	ProtocolTypesSaml2p        = "saml2p"
)

const (
	TokenTypesIdentityToken = "id_token"
	TokenTypesAccessToken   = "access_token"
)

type ScopeRequirement int

const (
	ScopeRequirementNone ScopeRequirement = iota
	ScopeRequirementResourceOnly
	ScopeRequirementIdentityOnly
	ScopeRequirementIdentity
)

const (
	DisplayModesPage  = "page"
	DisplayModesPopup = "popup"
	DisplayModesTouch = "touch"
	DisplayModesWap   = "wap"
)

var (
	SupportedResponseTypes []string = []string{
		ResponseTypesCode,
		ResponseTypesToken,
		ResponseTypesIdToken,
		ResponseTypesIdTokenToken,
		ResponseTypesCodeIdToken,
		ResponseTypesCodeToken,
		ResponseTypesCodeIdTokenToken,
	}

	ResponseTypeToGrantTypeMapping = map[string]string{
		ResponseTypesCode:             GrantTypeAuthorizationCode,
		ResponseTypesToken:            GrantTypeImplicit,
		ResponseTypesIdToken:          GrantTypeImplicit,
		ResponseTypesIdTokenToken:     GrantTypeImplicit,
		ResponseTypesCodeIdToken:      GrantTypeHybrid,
		ResponseTypesCodeToken:        GrantTypeHybrid,
		ResponseTypesCodeIdTokenToken: GrantTypeHybrid,
	}

	AllowedResponseModesForGrantType = map[string][]string{
		GrantTypeAuthorizationCode: {ResponseModesQuery, ResponseModesFormPost, ResponseModesFragment},
		GrantTypeHybrid:            {ResponseModesFragment, ResponseModesFormPost},
		GrantTypeImplicit:          {ResponseModesFragment, ResponseModesFormPost},
	}

	AllowedGrantTypesForAuthorizeEndpoint = []string{
		GrantTypeAuthorizationCode,
		GrantTypeImplicit,
		GrantTypeHybrid,
	}

	SupportedCodeChallengeMethods = []string{
		CodeChallengeMethodsPlain,
		CodeChallengeMethodsSha256,
	}

	SupportedResponseModes = []string{
		ResponseModesFormPost,
		ResponseModesQuery,
		ResponseModesFragment,
	}

	SupportedPromptModes = []string{
		PromptModesNone,
		PromptModesLogin,
		PromptModesConsent,
		PromptModesSelectAccount,
	}

	SupportedDisplayModes = []string{
		DisplayModesPage,
		DisplayModesPopup,
		DisplayModesTouch,
		DisplayModesWap,
	}

	ResponseTypeToScopeRequirement = map[string]ScopeRequirement{
		ResponseTypesCode:             ScopeRequirementNone,
		ResponseTypesToken:            ScopeRequirementResourceOnly,
		ResponseTypesIdToken:          ScopeRequirementIdentityOnly,
		ResponseTypesIdTokenToken:     ScopeRequirementIdentity,
		ResponseTypesCodeIdToken:      ScopeRequirementIdentity,
		ResponseTypesCodeToken:        ScopeRequirementIdentity,
		ResponseTypesCodeIdTokenToken: ScopeRequirementIdentity,
	}

	ScopeToClaimsMapping = map[string][]string{
		StandardScopesProfile: {
			JwtClaimTypesName,
			JwtClaimTypesFamilyName,
			JwtClaimTypesGivenName,
			JwtClaimTypesMiddleName,
			JwtClaimTypesNickName,
			JwtClaimTypesPreferredUserName,
			JwtClaimTypesProfile,
			JwtClaimTypesPicture,
			JwtClaimTypesWebSite,
			JwtClaimTypesGender,
			JwtClaimTypesBirthDate,
			JwtClaimTypesZoneInfo,
			JwtClaimTypesLocale,
			JwtClaimTypesUpdatedAt,
		},
		StandardScopesEmail: {
			JwtClaimTypesEmail,
			JwtClaimTypesEmailVerified,
		},
		StandardScopesAddress: {
			JwtClaimTypesAddress,
		},
		StandardScopesPhone: {
			JwtClaimTypesPhoneNumber,
			JwtClaimTypesPhoneNumberVerified,
		},
		StandardScopesOpenId: {
			JwtClaimTypesSubject,
		},
	}
)

const (
	KnownAcrValuesHomeRealm = "idp:"
	KnownAcrValuesTenant    = "tenant:"
)

var (
	KnownAcrValuesAll = []string{
		KnownAcrValuesHomeRealm,
		KnownAcrValuesTenant,
	}
)

const (
	AuthorizeRequestScope               = "scope"
	AuthorizeRequestRequest             = "request"
	AuthorizeRequestCodeChallengeMethod = "code_challenge_method"
	AuthorizeRequestCodeChallenge       = "code_challenge"
	AuthorizeRequestAcrValues           = "acr_values"
	AuthorizeRequestLoginHint           = "login_hint"
	AuthorizeRequestIdTokenHint         = "id_token_hint"
	AuthorizeRequestUiLocales           = "ui_locales"
	AuthorizeRequestRequestUri          = "request_uri"
	AuthorizeRequestMaxAge              = "max_age"
	AuthorizeRequestDisplay             = "display"
	AuthorizeRequestNonce               = "nonce"
	AuthorizeRequestResponseMode        = "response_mode"
	AuthorizeRequestState               = "state"
	AuthorizeRequestRedirectUri         = "redirect_uri"
	AuthorizeRequestClientId            = "client_id"
	AuthorizeRequestResponseType        = "response_type"
	AuthorizeRequestPrompt              = "prompt"
	AuthorizeRequestResource            = "resource"
)

var (
	SuppressedPrompt = "suppressed_" + AuthorizeRequestPrompt
)

const (
	UIConstantsCookieMessageThreshold                   int = 2
	UIConstantsDefaultRoutePathParamsError                  = "errorId"
	UIConstantsDefaultRoutePathParamsLogin                  = "returnUrl"
	UIConstantsDefaultRoutePathParamsConsent                = "returnUrl"
	UIConstantsDefaultRoutePathParamsLogout                 = "logoutId"
	UIConstantsDefaultRoutePathParamsEndSessionCallback     = "endSessionId"
	UIConstantsDefaultRoutePathParamsCustom                 = "returnUrl"
	UIConstantsDefaultRoutePathParamsUserCode               = "userCode"
	UIConstantsDefaultRoutePathsLogin                       = "/account/login"
	UIConstantsDefaultRoutePathsLogout                      = "/account/logout"
	UIConstantsDefaultRoutePathsConsent                     = "/consent"
	UIConstantsDefaultRoutePathsError                       = "/home/error"
	UIConstantsDefaultRoutePathsDeviceVerification          = "/device"
)

const (
	PromptModesNone          = "none"
	PromptModesLogin         = "login"
	PromptModesConsent       = "consent"
	PromptModesSelectAccount = "select_account"
)

type AuthorizeErrors error

var (
	AuthorizeErrorsInvalidRequest           = errors.New("invalid_request")
	AuthorizeErrorsRequestUriNotSupported   = errors.New("request_uri_not_supported")
	AuthorizeErrorsRequestNotSupported      = errors.New("request_not_supported")
	AuthorizeErrorsInvalidRequestObject     = errors.New("invalid_request_object")
	AuthorizeErrorsInvalidRequestUri        = errors.New("invalid_request_uri")
	AuthorizeErrorsConsentRequired          = errors.New("consent_required")
	AuthorizeErrorsAccountSelectionRequired = errors.New("account_selection_required")
	AuthorizeErrorsRegistrationNotSupported = errors.New("registration_not_supported")
	AuthorizeErrorsLoginRequired            = errors.New("login_required")
	AuthorizeErrorsTemporarilyUnavailable   = errors.New("temporarily_unavailable")
	AuthorizeErrorsServerError              = errors.New("server_error")
	AuthorizeErrorsInvalidScope             = errors.New("invalid_scope")
	AuthorizeErrorsUnsupportedResponseType  = errors.New("unsupported_response_type")
	AuthorizeErrorsAccessDenied             = errors.New("access_denied")
	AuthorizeErrorsUnauthorizedClient       = errors.New("unauthorized_client")
	AuthorizeErrorsInteractionRequired      = errors.New("interaction_required")
	AuthorizeErrorsInvalidTarget            = errors.New("invalid_target")
)

var (
	InvalidOperationException = errors.New("invalid_operation")
	ArgumentNullException     = errors.New("argument_null_exception")
	ArgumentException         = errors.New("argument_exception")
	IOException               = errors.New("io_exception")
)

const (
	ClaimTypesTenant = "tenant"
)

const (
	JwtClaimTypesSubject                             = "sub"
	JwtClaimTypesAuthenticationMethod                = "amr"
	JwtClaimTypesSessionId                           = "sid"
	JwtClaimTypesAuthenticationContextClassReference = "acr"
	JwtClaimTypesAuthenticationTime                  = "auth_time"
	JwtClaimTypesAuthorizedParty                     = "azp"
	JwtClaimTypesAccessTokenHash                     = "at_hash"
	JwtClaimTypesAuthorizationCodeHash               = "c_hash"
	JwtClaimTypesStateHash                           = "s_hash"
	JwtClaimTypesNonce                               = "nonce"
	JwtClaimTypesJwtId                               = "jti"
	JwtClaimTypesEvents                              = "events"
	JwtClaimTypesClientId                            = "client_id"
	JwtClaimTypesScope                               = "scope"
	JwtClaimTypesActor                               = "act"
	JwtClaimTypesMayAct                              = "may_act"
	JwtClaimTypesId                                  = "id"
	JwtClaimTypesIdentityProvider                    = "idp"
	JwtClaimTypesRole                                = "role"
	JwtClaimTypesReferenceTokenId                    = "reference_token_id"
	JwtClaimTypesIssuedAt                            = "iat"
	JwtClaimTypesUpdatedAt                           = "updated_at"
	JwtClaimTypesExpiration                          = "exp"
	JwtClaimTypesNotBefore                           = "nbf"
	JwtClaimTypesName                                = "name"
	JwtClaimTypesGivenName                           = "given_name"
	JwtClaimTypesFamilyName                          = "family_name"
	JwtClaimTypesMiddleName                          = "middle_name"
	JwtClaimTypesNickName                            = "nickname"
	JwtClaimTypesPreferredUserName                   = "preferred_username"
	JwtClaimTypesProfile                             = "profile"
	JwtClaimTypesPicture                             = "picture"
	JwtClaimTypesWebSite                             = "website"
	JwtClaimTypesConfirmation                        = "cnf"
	JwtClaimTypesEmail                               = "email"
	JwtClaimTypesGender                              = "gender"
	JwtClaimTypesBirthDate                           = "birthdate"
	JwtClaimTypesZoneInfo                            = "zoneinfo"
	JwtClaimTypesLocale                              = "locale"
	JwtClaimTypesPhoneNumber                         = "phone_number"
	JwtClaimTypesPhoneNumberVerified                 = "phone_number_verified"
	JwtClaimTypesAddress                             = "address"
	JwtClaimTypesAudience                            = "aud"
	JwtClaimTypesIssuer                              = "iss"
	JwtClaimTypesEmailVerified                       = "email_verified"
	JwtClaimTypesAccessToken                         = "at"
	JwtClaimTypesAuthorizationRequest                = "oauth"
)

type JwtTypes string

const (
	JwtTypesAccessToken          JwtTypes = "at+jwt"
	JwtTypesAuthorizationRequest JwtTypes = "oauth-authz-req+jwt"
)

const (
	ProtocolRoutePathsConnectPathPrefix = "connect"
)

const (
	ParsedSecretTypesNoSecret        = "NoSecret"
	ParsedSecretTypesSharedSecret    = "SharedSecret"
	ParsedSecretTypesX509Certificate = "X509Certificate"
	ParsedSecretTypesJwtBearer       = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

const (
	SecretTypesSharedSecret              = "SharedSecret"
	SecretTypesX509CertificateThumbprint = "X509Thumbprint"
	SecretTypesX509CertificateName       = "X509Name"
	SecretTypesX509CertificateBase64     = "X509CertificateBase64"
	SecretTypesJsonWebKey                = "JWK"
)

var (
	ProtocolRoutePathsAuthorize                 = ProtocolRoutePathsConnectPathPrefix + "/authorize"
	ProtocolRoutePathsAuthorizeCallback         = ProtocolRoutePathsAuthorize + "/callback"
	ProtocolRoutePathsDiscoveryConfiguration    = "/.well-known/openid-configuration"
	ProtocolRoutePathsDiscoveryWebKeys          = ProtocolRoutePathsDiscoveryConfiguration + "/jwks"
	ProtocolRoutePathsBackchannelAuthentication = ProtocolRoutePathsConnectPathPrefix + "/ciba"
	ProtocolRoutePathsToken                     = ProtocolRoutePathsConnectPathPrefix + "/token"
	ProtocolRoutePathsRevocation                = ProtocolRoutePathsConnectPathPrefix + "/revocation"
	ProtocolRoutePathsUserInfo                  = ProtocolRoutePathsConnectPathPrefix + "/userinfo"
	ProtocolRoutePathsIntrospection             = ProtocolRoutePathsConnectPathPrefix + "/introspect"
	ProtocolRoutePathsEndSession                = ProtocolRoutePathsConnectPathPrefix + "/endsession"
	ProtocolRoutePathsEndSessionCallback        = ProtocolRoutePathsEndSession + "/callback"
	ProtocolRoutePathsCheckSession              = ProtocolRoutePathsConnectPathPrefix + "/checksession"
	ProtocolRoutePathsDeviceAuthorization       = ProtocolRoutePathsConnectPathPrefix + "/deviceauthorization"
	ProtocolRoutePathsMtlsPathPrefix            = ProtocolRoutePathsConnectPathPrefix + "/mtls"
	ProtocolRoutePathsMtlsToken                 = ProtocolRoutePathsMtlsPathPrefix + "/token"
	ProtocolRoutePathsMtlsRevocation            = ProtocolRoutePathsMtlsPathPrefix + "/revocation"
	ProtocolRoutePathsMtlsIntrospection         = ProtocolRoutePathsMtlsPathPrefix + "/introspect"
	ProtocolRoutePathsMtlsDeviceAuthorization   = ProtocolRoutePathsMtlsPathPrefix + "/deviceauthorization"
)

const (
	EndpointNamesAuthorize                 = "Authorize"
	EndpointNamesBackchannelAuthentication = "BackchannelAuthentication"
	EndpointNamesToken                     = "Token"
	EndpointNamesDeviceAuthorization       = "DeviceAuthorization"
	EndpointNamesDiscovery                 = "Discovery"
	EndpointNamesIntrospection             = "Introspection"
	EndpointNamesRevocation                = "Revocation"
	EndpointNamesEndSession                = "Endsession"
	EndpointNamesCheckSession              = "Checksession"
	EndpointNamesUserInfo                  = "Userinfo"
)

var (
	CorsPaths = []string{
		ProtocolRoutePathsDiscoveryConfiguration,
		ProtocolRoutePathsDiscoveryWebKeys,
		ProtocolRoutePathsToken,
		ProtocolRoutePathsUserInfo,
		ProtocolRoutePathsRevocation,
	}
)

const (
	// REQUIRED. Informs the Authorization Server that the Client is making an OpenID Connect request. If the openidscope value is not present, the behavior is entirely unspecified.
	StandardScopesOpenId = "openid"

	// OPTIONAL. This scope value requests access to the End-User's default profile Claims, which are: name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
	StandardScopesProfile = "profile"

	// OPTIONAL. This scope value requests access to the email and email_verified Claims.
	StandardScopesEmail = "email"

	// OPTIONAL. This scope value requests access to the address Claim.
	StandardScopesAddress = "address"

	// OPTIONAL. This scope value requests access to the phone_number and phone_number_verified Claims.
	StandardScopesPhone = "phone"

	// This scope value MUST NOT be used with the OpenID Connect Implicit Client Implementer's Guide 1.0. See the OpenID Connect Basic Client Implementer's Guide 1.0 (http://openid.net/specs/openid-connect-implicit-1_0.html#OpenID.Basic) for its usage in that subset of OpenID Connect.
	StandardScopesOfflineAccess = "offline_access"
)

type TokenUsage int

const (
	TokenUsageOneTimeOnly TokenUsage = iota
	TokenUsageReUse
)

type TokenExpiration int

const (
	TokenExpirationSliding TokenExpiration = iota
	TokenExpirationAbsolute
)

type AccessTokenType int

const (
	AccessTokenTypeJwt AccessTokenType = iota
	AccessTokenTypeReference
)

var (
	GrantTypesImplicit = []string{
		GrantTypeImplicit,
	}

	GrantTypesImplicitAndClientCredentials = []string{
		GrantTypeImplicit, GrantTypeClientCredentials,
	}

	GrantTypesCode = []string{
		GrantTypeAuthorizationCode,
	}
	GrantTypesCodeAndClientCredentials = []string{
		GrantTypeAuthorizationCode, GrantTypeClientCredentials,
	}
	GrantTypesHybrid = []string{
		GrantTypeHybrid,
	}
	GrantTypesHybridAndClientCredentials = []string{
		GrantTypeHybrid, GrantTypeClientCredentials,
	}
	GrantTypesClientCredentials = []string{
		GrantTypeClientCredentials,
	}
	GrantTypesPassword = []string{
		GrantTypePassword,
	}
	GrantTypesResourceOwnerPasswordAndClientCredentials = []string{
		GrantTypePassword, GrantTypeClientCredentials,
	}
	GrantTypesDeviceFlow = []string{
		GrantTypeDeviceCode,
	}
	GrantTypesBackchannelAuthentication = []string{
		GrantTypeBackchannelAuthentication,
	}
)

const (
	ProfileIsActiveCallersAuthorizeEndpoint                   = "AuthorizeEndpoint"
	ProfileIsActiveCallersIdentityTokenValidation             = "IdentityTokenValidation"
	ProfileIsActiveCallersAccessTokenValidation               = "AccessTokenValidation"
	ProfileIsActiveCallersResourceOwnerValidation             = "ResourceOwnerValidation"
	ProfileIsActiveCallersExtensionGrantValidation            = "ExtensionGrantValidation"
	ProfileIsActiveCallersRefreshTokenValidation              = "RefreshTokenValidation"
	ProfileIsActiveCallersAuthorizationCodeValidation         = "AuthorizationCodeValidation"
	ProfileIsActiveCallersUserInfoRequestValidation           = "UserInfoRequestValidation"
	ProfileIsActiveCallersDeviceCodeValidation                = "DeviceCodeValidation"
	ProfileIsActiveCallersBackchannelAuthenticationValidation = "BackchannelAuthenticationValidation"
)

// src/Storage/Models/Enums.cs

type CspLevel int

const (
	CspLevelOne CspLevel = iota
	CspLevelTwo
)

const (
	AuthorizationParamsStoreMessageStoreIdParameterName = "authzId"
)

type TokenRequestErrors int

const (
	TokenRequestErrorsInvalidRequest TokenRequestErrors = iota
	TokenRequestErrorsInvalidClient
	TokenRequestErrorsInvalidGrant
	TokenRequestErrorsUnauthorizedClient
	TokenRequestErrorsUnsupportedGrantType
	TokenRequestErrorsInvalidScope
	TokenRequestErrorsInvalidTarget
)

var (
	TokenErrorsInvalidRequest          = errors.New("invalid_request")
	TokenErrorsInvalidClient           = errors.New("invalid_client")
	TokenErrorsInvalidGrant            = errors.New("invalid_grant")
	TokenErrorsUnauthorizedClient      = errors.New("unauthorized_client")
	TokenErrorsUnsupportedGrantType    = errors.New("unsupported_grant_type")
	TokenErrorsUnsupportedResponseType = errors.New("unsupported_response_type")
	TokenErrorsInvalidScope            = errors.New("invalid_scope")
	TokenErrorsAuthorizationPending    = errors.New("authorization_pending")
	TokenErrorsAccessDenied            = errors.New("access_denied")
	TokenErrorsSlowDown                = errors.New("slow_down")
	TokenErrorsExpiredToken            = errors.New("expired_token")
	TokenErrorsInvalidTarget           = errors.New("invalid_target")
)

const (
	BackchannelTokenDeliveryModesPoll = "poll"
	BackchannelTokenDeliveryModesPing = "ping"
	BackchannelTokenDeliveryModesPush = "push"
)

const (
	DiscoveryIssuer                                                    = "issuer"
	DiscoveryDisplayValuesSupported                                    = "display_values_supported"
	DiscoveryAcrValuesSupported                                        = "acr_values_supported"
	DiscoveryIdTokenEncryptionAlgorithmsSupported                      = "id_token_encryption_alg_values_supported"
	DiscoveryIdTokenEncryptionEncValuesSupported                       = "id_token_encryption_enc_values_supported"
	DiscoveryIdTokenSigningAlgorithmsSupported                         = "id_token_signing_alg_values_supported"
	DiscoveryOpPolicyUri                                               = "op_policy_uri"
	DiscoveryOpTosUri                                                  = "op_tos_uri"
	DiscoveryRequestObjectEncryptionAlgorithmsSupported                = "request_object_encryption_alg_values_supported"
	DiscoveryRequestObjectEncryptionEncValuesSupported                 = "request_object_encryption_enc_values_supported"
	DiscoveryRequestObjectSigningAlgorithmsSupported                   = "request_object_signing_alg_values_supported"
	DiscoveryRequestParameterSupported                                 = "request_parameter_supported"
	DiscoveryRequestUriParameterSupported                              = "request_uri_parameter_supported"
	DiscoveryRequireRequestUriRegistration                             = "require_request_uri_registration"
	DiscoveryServiceDocumentation                                      = "service_documentation"
	DiscoveryTokenEndpointAuthSigningAlgorithmsSupported               = "token_endpoint_auth_signing_alg_values_supported"
	DiscoveryUILocalesSupported                                        = "ui_locales_supported"
	DiscoveryUserInfoEncryptionAlgorithmsSupported                     = "userinfo_encryption_alg_values_supported"
	DiscoveryUserInfoEncryptionEncValuesSupported                      = "userinfo_encryption_enc_values_supported"
	DiscoveryUserInfoSigningAlgorithmsSupported                        = "userinfo_signing_alg_values_supported"
	DiscoveryTlsClientCertificateBoundAccessTokens                     = "tls_client_certificate_bound_access_tokens"
	DiscoveryAuthorizationResponseIssParameterSupported                = "authorization_response_iss_parameter_supported"
	DiscoveryBackchannelTokenDeliveryModesSupported                    = "backchannel_token_delivery_modes_supported"
	DiscoveryBackchannelAuthenticationEndpoint                         = "backchannel_authentication_endpoint"
	DiscoveryClaimTypesSupported                                       = "claim_types_supported"
	DiscoveryBackchannelAuthenticationRequestSigningAlgValuesSupported = "backchannel_authentication_request_signing_alg_values_supported"
	DiscoveryClaimsParameterSupported                                  = "claims._parameter_supported"
	DiscoveryTokenEndpointAuthenticationMethodsSupported               = "token_endpoint_auth_methods_supported"
	DiscoveryAuthorizationEndpoint                                     = "authorization_endpoint"
	DiscoveryDeviceAuthorizationEndpoint                               = "device_authorization_endpoint"
	DiscoveryTokenEndpoint                                             = "token_endpoint"
	DiscoveryUserInfoEndpoint                                          = "userinfo_endpoint"
	DiscoveryIntrospectionEndpoint                                     = "introspection_endpoint"
	DiscoveryRevocationEndpoint                                        = "revocation_endpoint"
	DiscoveryDiscoveryEndpoint                                         = ".well-known/openid-configuration"
	DiscoveryJwksUri                                                   = "jwks_uri"
	DiscoveryEndSessionEndpoint                                        = "end_session_endpoint"
	DiscoveryCheckSessionIframe                                        = "check_session_iframe"
	DiscoveryRegistrationEndpoint                                      = "registration_endpoint"
	DiscoveryMtlsEndpointAliases                                       = "mtls_endpoint_aliases"
	DiscoveryFrontChannelLogoutSupported                               = "frontchannel_logout_supported"
	DiscoveryFrontChannelLogoutSessionSupported                        = "frontchannel_logout_session_supported"
	DiscoveryBackchannelLogoutSupported                                = "backchannel_logout_supported"
	DiscoveryBackchannelLogoutSessionSupported                         = "backchannel_logout_session_supported"
	DiscoveryGrantTypesSupported                                       = "grant_types_supported"
	DiscoveryCodeChallengeMethodsSupported                             = "code_challenge_methods_supported"
	DiscoveryScopesSupported                                           = "scopes_supported"
	DiscoverySubjectTypesSupported                                     = "subject_types_supported"
	DiscoveryResponseModesSupported                                    = "response_modes_supported"
	DiscoveryResponseTypesSupported                                    = "response_types_supported"
	DiscoveryClaimsSupported                                           = "claims._supported"
	DiscoveryClaimsLocalesSupported                                    = "claims._locales_supported"
	DiscoveryBackchannelUserCodeParameterSupported                     = "backchannel_user_code_parameter_supported"
)

const (
	EndpointAuthenticationMethodsPostBody                = "client_secret_post"
	EndpointAuthenticationMethodsBasicAuthentication     = "client_secret_basic"
	EndpointAuthenticationMethodsPrivateKeyJwt           = "private_key_jwt"
	EndpointAuthenticationMethodsTlsClientAuth           = "tls_client_auth"
	EndpointAuthenticationMethodsSelfSignedTlsClientAuth = "self_signed_tls_client_auth"
)

const (
	SecurityAlgorithmsAes128Encryption          = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	SecurityAlgorithmsHmacSha384Signature       = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
	SecurityAlgorithmsHmacSha512Signature       = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
	SecurityAlgorithmsRsaSha256Signature        = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SecurityAlgorithmsRsaSha384Signature        = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SecurityAlgorithmsRsaSha512Signature        = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SecurityAlgorithmsRsaSsaPssSha256Signature  = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	SecurityAlgorithmsRsaSsaPssSha384Signature  = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1"
	SecurityAlgorithmsRsaSsaPssSha512Signature  = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"
	SecurityAlgorithmsEcdsaSha256               = "ES256"
	SecurityAlgorithmsEcdsaSha384               = "ES384"
	SecurityAlgorithmsHmacSha256Signature       = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
	SecurityAlgorithmsEcdsaSha512               = "ES512"
	SecurityAlgorithmsHmacSha384                = "HS384"
	SecurityAlgorithmsHmacSha512                = "HS512"
	SecurityAlgorithmsNone                      = "none"
	SecurityAlgorithmsRsaSha256                 = "RS256"
	SecurityAlgorithmsRsaSha384                 = "RS384"
	SecurityAlgorithmsRsaSha512                 = "RS512"
	SecurityAlgorithmsRsaSsaPssSha256           = "PS256"
	SecurityAlgorithmsRsaSsaPssSha384           = "PS384"
	SecurityAlgorithmsRsaSsaPssSha512           = "PS512"
	SecurityAlgorithmsAes128CbcHmacSha256       = "A128CBC-HS256"
	SecurityAlgorithmsHmacSha256                = "HS256"
	SecurityAlgorithmsAes192CbcHmacSha384       = "A192CBC-HS384"
	SecurityAlgorithmsEcdsaSha512Signature      = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	SecurityAlgorithmsEcdsaSha256Signature      = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SecurityAlgorithmsAes192Encryption          = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	SecurityAlgorithmsAes256Encryption          = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	SecurityAlgorithmsDesEncryption             = "http://www.w3.org/2001/04/xmlenc#des-cbc"
	SecurityAlgorithmsAes128KeyWrap             = "http://www.w3.org/2001/04/xmlenc#kw-aes128"
	SecurityAlgorithmsAes192KeyWrap             = "http://www.w3.org/2001/04/xmlenc#kw-aes192"
	SecurityAlgorithmsAes256KeyWrap             = "http://www.w3.org/2001/04/xmlenc#kw-aes256"
	SecurityAlgorithmsRsaV15KeyWrap             = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	SecurityAlgorithmsRipemd160Digest           = "http://www.w3.org/2001/04/xmlenc#ripemd160"
	SecurityAlgorithmsRsaOaepKeyWrap            = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	SecurityAlgorithmsAes128KW                  = "A128KW"
	SecurityAlgorithmsEcdsaSha384Signature      = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SecurityAlgorithmsAes256KW                  = "A256KW"
	SecurityAlgorithmsRsaOAEP                   = "RSA-OAEP"
	SecurityAlgorithmsExclusiveC14n             = "http://www.w3.org/2001/10/xml-exc-c14n#"
	SecurityAlgorithmsExclusiveC14nWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	SecurityAlgorithmsEnvelopedSignature        = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	SecurityAlgorithmsSha256Digest              = "http://www.w3.org/2001/04/xmlenc#sha256"
	SecurityAlgorithmsSha384Digest              = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	SecurityAlgorithmsSha512Digest              = "http://www.w3.org/2001/04/xmlenc#sha512"
	SecurityAlgorithmsSha256                    = "SHA256"
	SecurityAlgorithmsSha384                    = "SHA384"
	SecurityAlgorithmsSha512                    = "SHA512"
	SecurityAlgorithmsRsaPKCS1                  = "RSA1_5"
	SecurityAlgorithmsAes256CbcHmacSha512       = "A256CBC-HS512"
)

const (
	SigningAlgorithmsRSA_SHA_256 = "RS256"
)

var (
	SupportedSigningAlgorithms = []string{
		SecurityAlgorithmsRsaSha256,
		SecurityAlgorithmsRsaSha384,
		SecurityAlgorithmsRsaSha512,
		SecurityAlgorithmsRsaSsaPssSha256,
		SecurityAlgorithmsRsaSsaPssSha384,
		SecurityAlgorithmsRsaSsaPssSha512,
		SecurityAlgorithmsEcdsaSha256,
		SecurityAlgorithmsEcdsaSha384,
		SecurityAlgorithmsEcdsaSha512,
	}
)

const (
	EndSessionRequestIdTokenHint           = "id_token_hint"
	EndSessionRequestPostLogoutRedirectUri = "post_logout_redirect_uri"
	EndSessionRequestState                 = "state"
	EndSessionRequestSid                   = "sid"
	EndSessionRequestIssuer                = "iss"
	EndSessionRequestUiLocales             = "ui_locales"
)

const (
	PersistedGrantTypesAuthorizationCode                = "authorization_code"
	PersistedGrantTypesBackchannelAuthenticationRequest = "ciba"
	PersistedGrantTypesReferenceToken                   = "reference_token"
	PersistedGrantTypesRefreshToken                     = "refresh_token"
	PersistedGrantTypesUserConsent                      = "user_consent"
	PersistedGrantTypesDeviceCode                       = "device_code"
	PersistedGrantTypesUserCode                         = "user_code"
)

var (
	ProtectedResourceErrorsInvalidToken      = errors.New("invalid_token")
	ProtectedResourceErrorsExpiredToken      = errors.New("expired_token")
	ProtectedResourceErrorsInvalidRequest    = errors.New("invalid_request")
	ProtectedResourceErrorsInsufficientScope = errors.New("insufficient_scope")
)

var (
	ProtectedResourceErrorStatusCodes = map[error]int{
		ProtectedResourceErrorsInvalidToken:      401,
		ProtectedResourceErrorsExpiredToken:      401,
		ProtectedResourceErrorsInvalidRequest:    400,
		ProtectedResourceErrorsInsufficientScope: 403,
	}
)

const (
	UserCodeTypesNumeric = "Numeric"
)

const (
	TokenTypeHintsRefreshToken = "refresh_token"
	TokenTypeHintsAccessToken  = "access_token"
)

var (
	SupportedTokenTypeHints = []string{
		TokenTypeHintsRefreshToken,
		TokenTypeHintsAccessToken,
	}
)

var (
	RevocationErrorsUnsupportedTokenType = errors.New("unsupported_token_type")
)

const (
	AuthenticationSchemesAuthorizationHeaderBearer = "Bearer"
	AuthenticationSchemesFormPostBearer            = "access_token"
	AuthenticationSchemesQueryStringBearer         = "access_token"
	AuthenticationSchemesAuthorizationHeaderPop    = "PoP"
	AuthenticationSchemesFormPostPop               = "pop_access_token"
	AuthenticationSchemesQueryStringPop            = "pop_access_token"
)

const (
	ProfileDataCallersUserInfoEndpoint            = "UserInfoEndpoint"
	ProfileDataCallersClaimsProviderIdentityToken = "ClaimsProviderIdentityToken"
	ProfileDataCallersClaimsProviderAccessToken   = "ClaimsProviderAccessToken"
)

const (
	ProtocolSignOutLogoutUriParameterName  = "wa"
	ProtocolSignOutLogoutUriParameterValue = "wsignoutcleanup1.0"
)

var (
	// filter for claims. from an incoming access token (e.g. used at the user profile endpoint)
	ProtocolClaimsFilter = []string{
		JwtClaimTypesAccessTokenHash,
		JwtClaimTypesAudience,
		JwtClaimTypesAuthorizedParty,
		JwtClaimTypesAuthorizationCodeHash,
		JwtClaimTypesClientId,
		JwtClaimTypesExpiration,
		JwtClaimTypesIssuedAt,
		JwtClaimTypesIssuer,
		JwtClaimTypesJwtId,
		JwtClaimTypesNonce,
		JwtClaimTypesNotBefore,
		JwtClaimTypesReferenceTokenId,
		JwtClaimTypesSessionId,
		JwtClaimTypesScope,
	}

	// filter list for claims. returned from profile service prior to creating tokens
	ClaimsServiceFilterClaimTypes = []string{
		// TODO: consider JwtClaimTypesAuthenticationContextClassReference,
		JwtClaimTypesAccessTokenHash,
		JwtClaimTypesAudience,
		JwtClaimTypesAuthenticationMethod,
		JwtClaimTypesAuthenticationTime,
		JwtClaimTypesAuthorizedParty,
		JwtClaimTypesAuthorizationCodeHash,
		JwtClaimTypesClientId,
		JwtClaimTypesExpiration,
		JwtClaimTypesIdentityProvider,
		JwtClaimTypesIssuedAt,
		JwtClaimTypesIssuer,
		JwtClaimTypesJwtId,
		JwtClaimTypesNonce,
		JwtClaimTypesNotBefore,
		JwtClaimTypesReferenceTokenId,
		JwtClaimTypesSessionId,
		JwtClaimTypesSubject,
		JwtClaimTypesScope,
		JwtClaimTypesConfirmation,
	}

	JwtRequestClaimTypesFilter = []string{
		JwtClaimTypesAudience,
		JwtClaimTypesExpiration,
		JwtClaimTypesIssuedAt,
		JwtClaimTypesIssuer,
		JwtClaimTypesNotBefore,
		JwtClaimTypesJwtId,
	}
)

const (
	HttpClientsDefaultTimeoutSeconds       = 10
	HttpClientsJwtRequestUriHttpClient     = "gois:JwtRequestUriClient"
	HttpClientsBackChannelLogoutHttpClient = "gois:BackchannelLogoutClient"
)

const (
	EnvironmentKeysWicketBasePath      = "wicket:BasePath"
	EnvironmentKeysWicketOrigin        = "wicket:Origin" // todo: deprecate
	EnvironmentKeysWicketSignOutCalled = "wicket:SignOutCalled"
)
