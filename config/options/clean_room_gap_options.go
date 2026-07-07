// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

type CleanRoomGapOptions struct {
	Enabled bool
}

func NewCleanRoomGapOptions() *CleanRoomGapOptions {
	return &CleanRoomGapOptions{Enabled: false}
}

type MutualTlsOptions struct {
	Enabled    bool
	DomainName string
}

func NewMutualTlsOptions() *MutualTlsOptions {
	return &MutualTlsOptions{Enabled: false}
}

type CleanRoomKeyGapOptions struct {
	Enabled bool
}

func NewCleanRoomKeyGapOptions() *CleanRoomKeyGapOptions {
	return &CleanRoomKeyGapOptions{Enabled: false}
}

type CleanRoomProviderGapOptions struct {
	Enabled bool
}

func NewCleanRoomProviderGapOptions() *CleanRoomProviderGapOptions {
	return &CleanRoomProviderGapOptions{Enabled: false}
}

type CleanRoomSessionGapOptions struct {
	Enabled bool
}

func NewCleanRoomSessionGapOptions() *CleanRoomSessionGapOptions {
	return &CleanRoomSessionGapOptions{Enabled: false}
}
