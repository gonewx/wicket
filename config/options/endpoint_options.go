// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

type EndpointsOptions struct {
	EnableAuthorizeEndpoint           bool
	EnableJwtRequestUri               bool
	EnableTokenEndpoint               bool
	EnableUserInfoEndpoint            bool
	EnableDiscoveryEndpoint           bool
	EnableEndSessionEndpoint          bool
	EnableCheckSessionEndpoint        bool
	EnableTokenRevocationEndpoint     bool
	EnableIntrospectionEndpoint       bool
	EnableDeviceAuthorizationEndpoint bool
	EnableCleanRoomGapEndpoint        bool
}

func NewEndpointsOptions() *EndpointsOptions {
	return &EndpointsOptions{
		EnableAuthorizeEndpoint:           true,
		EnableJwtRequestUri:               false,
		EnableTokenEndpoint:               true,
		EnableUserInfoEndpoint:            true,
		EnableDiscoveryEndpoint:           true,
		EnableEndSessionEndpoint:          true,
		EnableCheckSessionEndpoint:        true,
		EnableTokenRevocationEndpoint:     true,
		EnableIntrospectionEndpoint:       true,
		EnableDeviceAuthorizationEndpoint: true,
		EnableCleanRoomGapEndpoint:        true,
	}
}
