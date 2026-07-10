// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPropertiesItemsReuseInjectedReference(t *testing.T) {
	t.Parallel()

	injected := map[string]string{"foo": "bar"}
	properties := &Properties{Items: injected}

	require.Equal(t, injected, properties.Items)

	// A mutation through the original map is visible via the property object,
	// proving both sides share the same underlying reference rather than a copy.
	injected["baz"] = "quux"
	require.Equal(t, "quux", properties.Items["baz"])
}
