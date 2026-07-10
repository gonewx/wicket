// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"testing"

	"github.com/gonewx/wicket/auth"
	"github.com/stretchr/testify/require"
)

func TestSchemeProviderAddSchemeRejectsDuplicateName(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider()

	require.NoError(t, provider.AddScheme(auth.NewScheme("signin", "cookie")))

	err := provider.AddScheme(auth.NewScheme("signin", "cookie"))
	require.Error(t, err)
}

func TestSchemeProviderTryAddSchemeIsSilentOnDuplicate(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider()

	steps := []struct {
		name       string
		schemeName string
		want       bool
	}{
		{name: "first new name is added", schemeName: "signin", want: true},
		{name: "second new name is added", schemeName: "signin2", want: true},
		{name: "duplicate name is silently rejected", schemeName: "signin", want: false},
		{name: "third new name is added", schemeName: "signin3", want: true},
		{name: "another duplicate name is silently rejected", schemeName: "signin2", want: false},
	}

	for _, step := range steps {
		got := provider.TryAddScheme(auth.NewScheme(step.schemeName, "cookie"))
		require.Equalf(t, step.want, got, "step %q", step.name)
	}
}

func TestSchemeProviderGetSchemeExactName(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider()
	require.NoError(t, provider.AddScheme(auth.NewScheme("signin", "cookie")))

	require.NotNil(t, provider.GetScheme("signin"))
}
