// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

import "github.com/gonewx/wicket"

// Configures device flow
type DeviceFlowOptions struct {
	// Gets or sets the default type of the user code.
	// The default type of the user code.
	DefaultUserCodeType string

	// Gets or sets the polling interval in seconds.
	// The interval in seconds.
	Interval int
}

func NewDeviceFlowOptions() *DeviceFlowOptions {
	return &DeviceFlowOptions{
		DefaultUserCodeType: gois.UserCodeTypesNumeric,
		Interval:            5,
	}
}
