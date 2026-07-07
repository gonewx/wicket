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
		LogoutIdParameter:                   gois.UIConstantsDefaultRoutePathParamsLogout,
		ConsentUrl:                          gois.UIConstantsDefaultRoutePathsConsent,
		ConsentReturnUrlParameter:           gois.UIConstantsDefaultRoutePathParamsConsent,
		ErrorUrl:                            gois.UIConstantsDefaultRoutePathsError,
		ErrorIdParameter:                    gois.UIConstantsDefaultRoutePathParamsError,
		CustomRedirectReturnUrlParameter:    gois.UIConstantsDefaultRoutePathParamsCustom,
		CookieMessageThreshold:              gois.UIConstantsCookieMessageThreshold,
		DeviceVerificationUrl:               gois.UIConstantsDefaultRoutePathsDeviceVerification,
		DeviceVerificationUserCodeParameter: gois.UIConstantsDefaultRoutePathParamsUserCode,
	}
	return options
}
