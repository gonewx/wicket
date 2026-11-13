// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

import (
	"testing"

	"github.com/gonewx/wicket"

	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/stretchr/testify/require"
)

func TestWicketOptionsEntityNewFromNilReceiver(t *testing.T) {
	t.Parallel()

	var entity optspkg.Entity[*WicketOptions] = (*WicketOptions)(nil)

	require.Equal(t, NewWicketOptions(), entity.New())
}

// RFC 8628 §3.2: a client that is not told otherwise waits 5 seconds between
// polls, so the default options advertise and throttle with that interval.
func TestWicketOptionsDeviceFlowDefaults(t *testing.T) {
	t.Parallel()

	options := NewWicketOptions()

	require.Equal(t, 5, options.DeviceFlow.Interval)
	require.Equal(t, wicket.UserCodeTypesNumeric, options.DeviceFlow.DefaultUserCodeType)
}
