// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

import optspkg "github.com/gonewx/wicket/options"

var _ optspkg.Entity[*WicketOptions] = (*WicketOptions)(nil)

type WicketOptions struct {
	IssuerUri                                 string
	LowerCaseIssuerUri                        bool
	AccessTokenJwtType                        string
	EmitStaticAudienceClaim                   bool
	EmitScopesAsSpaceDelimitedStringInJwt     bool
	EmitIssuerIdentificationResponseParameter bool
	EmitStateHash                             bool
	StrictJarValidation                       bool
	ValidateTenantOnAuthorization             bool
	Endpoints                                 *EndpointsOptions
	Discovery                                 *DiscoveryOptions
	Authentication                            *AuthenticationOptions
	// Events                                    EventsOptions
	InputLengthRestrictions *InputLengthRestrictions
	UserInteraction         *UserInteractionOptions
	// Caching            CachingOptions
	Cors         *CorsOptions
	Csp          *CspOptions
	Validation   *ValidationOptions
	DeviceFlow   DeviceFlowOptions
	CleanRoomGap *CleanRoomGapOptions
	// Logging            LoggingOptions
	MutualTls        *MutualTlsOptions
	CleanRoomKeyGap  *CleanRoomKeyGapOptions
	PersistentGrants *PersistentGrantOptions
	// LicenseKey         string
	CleanRoomProviderGap *CleanRoomProviderGapOptions
	CleanRoomSessionGap  *CleanRoomSessionGapOptions
}

func NewWicketOptions() *WicketOptions {
	return &WicketOptions{
		LowerCaseIssuerUri:                        true,
		AccessTokenJwtType:                        "at+jwt",
		EmitIssuerIdentificationResponseParameter: true,
		Endpoints:      NewEndpointsOptions(),
		Discovery:      NewDiscoveryOptions(),
		Authentication: NewAuthenticationOptions(),
		// Events: NewEventsOptions(),
		InputLengthRestrictions: NewInputLengthRestrictions(),
		UserInteraction:         NewUserInteractionOptions(),
		// Caching: NewCachingOptions(),
		Cors:       NewCorsOptions(),
		Csp:        NewCspOptions(),
		Validation: NewValidationOptions(),
		// DeviceFlow: NewDeviceFlowOptions(),
		CleanRoomGap: NewCleanRoomGapOptions(),
		// Logging: NewLoggingOptions(),
		MutualTls:            NewMutualTlsOptions(),
		CleanRoomKeyGap:      NewCleanRoomKeyGapOptions(),
		PersistentGrants:     NewPersistentGrantOptions(),
		CleanRoomProviderGap: NewCleanRoomProviderGapOptions(),
		CleanRoomSessionGap:  NewCleanRoomSessionGapOptions(),
	}
}

// Entity[T] simulates dotnet's new() generic constraint on the Go side.
// OptionsFactory.Create instantiates options through zero.New().
func (o *WicketOptions) New() *WicketOptions {
	return NewWicketOptions()
}
