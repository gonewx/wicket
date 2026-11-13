// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

import (
	"github.com/gonewx/wicket"
)

type UserInteractionOptions struct {
	LoginUrl                            string
	LoginReturnUrlParameter             string
	LogoutUrl                           string
	LogoutIdParameter                   string
	ConsentUrl                          string
	ConsentReturnUrlParameter           string
	ErrorUrl                            string
	ErrorIdParameter                    string
	CustomRedirectReturnUrlParameter    string
	CookieMessageThreshold              int
	DeviceVerificationUrl               string
	DeviceVerificationUserCodeParameter string
	AllowOriginInReturnUrl              bool
}

func NewUserInteractionOptions() *UserInteractionOptions {
	options := &UserInteractionOptions{
		LogoutIdParameter:                   wicket.UIConstantsDefaultRoutePathParamsLogout,
		ConsentUrl:                          wicket.UIConstantsDefaultRoutePathsConsent,
		ConsentReturnUrlParameter:           wicket.UIConstantsDefaultRoutePathParamsConsent,
		ErrorUrl:                            wicket.UIConstantsDefaultRoutePathsError,
		ErrorIdParameter:                    wicket.UIConstantsDefaultRoutePathParamsError,
		CustomRedirectReturnUrlParameter:    wicket.UIConstantsDefaultRoutePathParamsCustom,
		CookieMessageThreshold:              wicket.UIConstantsCookieMessageThreshold,
		DeviceVerificationUrl:               wicket.UIConstantsDefaultRoutePathsDeviceVerification,
		DeviceVerificationUserCodeParameter: wicket.UIConstantsDefaultRoutePathParamsUserCode,
	}
	return options
}
