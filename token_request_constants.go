// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket

const (
	TokenRequestGrantType               = "grant_type"
	TokenRequestResource                = "resource"
	TokenRequestCode                    = "code"
	TokenRequestRedirectUri             = "redirect_uri"
	TokenRequestCodeVerifier            = "code_verifier"
	TokenRequestUserName                = "username"
	TokenRequestPassword                = "password"
	TokenRequestRefreshToken            = "refresh_token"
	TokenRequestDeviceCode              = "device_code"
	TokenRequestScope                   = "scope"
	TokenRequestAuthenticationRequestId = "auth_req_id"

	BackchannelAuthenticationRequestScope                   = "scope"
	BackchannelAuthenticationRequestResource                = "resource"
	BackchannelAuthenticationRequestClientNotificationToken = "client_notification_token"
	BackchannelAuthenticationRequestAcrValues               = "acr_values"
	BackchannelAuthenticationRequestLoginHintToken          = "login_hint_token"
	BackchannelAuthenticationRequestIdTokenHint             = "id_token_hint"
	BackchannelAuthenticationRequestLoginHint               = "login_hint"
	BackchannelAuthenticationRequestBindingMessage          = "binding_message"
	BackchannelAuthenticationRequestUserCode                = "user_code"
	BackchannelAuthenticationRequestRequestedExpiry         = "requested_expiry"
	BackchannelAuthenticationRequestRequest                 = "request"
)
