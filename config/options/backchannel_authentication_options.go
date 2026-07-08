// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

type BackchannelAuthenticationOptions struct {
	Enabled                    bool
	AllowedDeliveryModes       []string
	DefaultRequestLifetime     int
	DefaultPollingInterval     int
	SlowDownIntervalIncrement  int
	UserCodeParameterSupported bool
}

func NewBackchannelAuthenticationOptions() *BackchannelAuthenticationOptions {
	return &BackchannelAuthenticationOptions{
		Enabled:                    true,
		AllowedDeliveryModes:       []string{"poll"},
		DefaultRequestLifetime:     300,
		DefaultPollingInterval:     5,
		SlowDownIntervalIncrement:  5,
		UserCodeParameterSupported: true,
	}
}

type MutualTlsOptions struct {
	Enabled    bool
	DomainName string
}

func NewMutualTlsOptions() *MutualTlsOptions {
	return &MutualTlsOptions{Enabled: false}
}

type KeyManagementOptions struct {
	Enabled bool
}

func NewKeyManagementOptions() *KeyManagementOptions {
	return &KeyManagementOptions{Enabled: false}
}

type DynamicProviderOptions struct {
	Enabled bool
}

func NewDynamicProviderOptions() *DynamicProviderOptions {
	return &DynamicProviderOptions{Enabled: false}
}

type ServerSideSessionOptions struct {
	Enabled bool
}

func NewServerSideSessionOptions() *ServerSideSessionOptions {
	return &ServerSideSessionOptions{Enabled: false}
}
