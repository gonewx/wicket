// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

import (
	"testing"

	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/stretchr/testify/require"
)

func TestWicketOptionsEntityNewFromNilReceiver(t *testing.T) {
	t.Parallel()

	var entity optspkg.Entity[*WicketOptions] = (*WicketOptions)(nil)

	require.Equal(t, NewWicketOptions(), entity.New())
}
