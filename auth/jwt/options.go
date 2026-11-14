// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package jwt

import (
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/wicket/auth/core"
)

type Options struct {
	*core.SchemeOptions

	// Gets or sets if HTTPS is required for the metadata address or authority.
	// The default is true. This should be disabled only in development environments.
	RequireHttpsMetadata bool

	// Gets or sets the discovery endpoint for obtaining metadata
	MetadataAddress string

	// Gets or sets the Authority to use when making OpenIdConnect calls.
	Authority string

	// Gets or sets a single valid audience value for any received OpenIdConnect token.
	// This value is passed into TokenValidationParameters.ValidAudience if that property is empty.
	Audience string

	// Gets or sets the challenge to put in the "WWW-Authenticate" header.
	Challenge string

	// // The HttpMessageHandler used to retrieve metadata.
	// // This cannot be set at the same time as BackchannelCertificateValidator unless the value
	// // is a WebRequestHandler.
	// BackchannelHttpHandler HttpMessageHandler?
	BackchannelHttpHandler http.RoundTripper

	// // The Backchannel used to retrieve metadata.
	// Backchannel HttpClient

	// // Gets or sets the timeout when using the backchannel to make an http call.
	// BackchannelTimeout TimeSpan

	// Configuration provided directly by the developer. If provided, then MetadataAddress and the Backchannel properties
	// will not be used. This information should not be updated during request processing.
	// Configuration *openid.OpenIdConnectConfig

	// Responsible for retrieving, caching, and refreshing the configuration from metadata.
	// If not provided, then one will be created using the MetadataAddress and Backchannel properties.
	// ConfigurationManager IConfigurationManager<OpenIdConnectConfiguration>?

	// Gets or sets if a metadata refresh should be attempted after a SecurityTokenSignatureKeyNotFoundException. This allows for automatic
	// recovery in the event of a signature key rollover. This is enabled by default.
	RefreshOnIssuerKeyNotFound bool

	// Gets the ordered list of <see cref="ISecurityTokenValidator"/> used to validate access tokens.
	SecurityTokenValidators []SecurityTokenValidator

	// Gets or sets the parameters used to validate identity tokens.
	// TokenValidationParameters *TokenValidationParameters
	ValidateOptions []jwt.ValidateOption

	// Gets or sets the parameters used to validate identity tokens.
	// <remarks>Contains the types and definitions required for validating a token.</remarks>
	// <exception cref="ArgumentNullException">if 'value' is null.</exception>
	TokenValidationParameters *TokenValidationParameters

	// Defines whether the  token should be stored in the
	// <see cref="AuthenticationProperties"/> after a successful authorization.
	SaveToken bool

	// Defines whether the token validation errors should be returned to the caller.
	// Enabled by default, this option can be disabled to prevent the JWT handler
	// from returning an error and an error_description in the WWW-Authenticate header.
	IncludeErrorDetails bool

	// Gets or sets the <see cref="MapInboundClaims"/> property on the default instance of <see cref="JwtSecurityTokenHandler"/> in SecurityTokenValidators, which is used when determining
	// whether or not to map claim types that are extracted when validating a <see cref="JwtSecurityToken"/>.
	// <para>If this is set to true, the Claim Type is set to the JSON claim 'name' after translating using this mapping. Otherwise, no mapping occurs.</para>
	// <para>The default value is true.</para>
	// public bool MapInboundClaims
	// {
	//     get => _defaultHandler.MapInboundClaims;
	//     set => _defaultHandler.MapInboundClaims = value;
	// }

	// 1 day is the default time interval that afterwards, <see cref="ConfigurationManager" /> will obtain new configuration.
	AutomaticRefreshInterval time.Duration

	// The minimum time between <see cref="ConfigurationManager" /> retrievals, in the event that a retrieval failed, or that a refresh was explicitly requested. 30 seconds is the default.
	RefreshInterval time.Duration

	// CertificateBindingSource, when set, makes the handler fail a token bound
	// to a client certificate (cnf / x5t#S256, RFC 8705 §3) unless the request
	// presents that certificate as read from this source. Nil disables the check.
	// While it is set, a token produced by a custom SecurityTokenValidator (any
	// SecurityToken other than the built-in handler's) fails authentication.
	CertificateBindingSource CertificateSource
}

func NewOptions() *Options {
	return &Options{
		SchemeOptions: core.NewSchemeOptions(),
		SecurityTokenValidators: []SecurityTokenValidator{
			NewSecurityTokenHandler(),
		},
		TokenValidationParameters: NewTokenValidationParameters(),
	}
}

func (o *Options) New() *Options {
	return NewOptions()
}

// The object provided by the application to process events raised by the  authentication handler.
// The application may implement the interface fully, or it may create an instance of JwtEvents
// and assign delegates only to the events it wants to process.
func (o *Options) Events() any {
	return o.SchemeOptions.Events()
}

func (o *Options) SetEvents(v any) {
	o.SchemeOptions.SetEvents(v)
}
