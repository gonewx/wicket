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

	provider := NewSchemeProvider(auth.NewOptions())

	require.NoError(t, provider.AddScheme(auth.NewScheme("signin", "cookie")))

	err := provider.AddScheme(auth.NewScheme("signin", "cookie"))
	require.Error(t, err)
}

func TestSchemeProviderTryAddSchemeIsSilentOnDuplicate(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider(auth.NewOptions())

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

	provider := NewSchemeProvider(auth.NewOptions())
	require.NoError(t, provider.AddScheme(auth.NewScheme("signin", "cookie")))

	require.NotNil(t, provider.GetScheme("signin"))
}

func TestSchemeProviderDefaultsAreNilWithoutConfiguration(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider(auth.NewOptions())
	require.NoError(t, provider.AddScheme(auth.NewScheme("only", "cookie")))

	// Default resolution comes strictly from configuration and never falls back
	// to an implicitly-chosen registered scheme.
	require.Nil(t, provider.GetDefaultForbidScheme())
	require.Nil(t, provider.GetDefaultAuthenticateScheme())
	require.Nil(t, provider.GetDefaultChallengeScheme())
	require.Nil(t, provider.GetDefaultSignInScheme())
	require.Nil(t, provider.GetDefaultSignOutScheme())
}

func TestSchemeProviderOverallDefaultBacksAllCategories(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider(&auth.Options{DefaultScheme: "B"})
	require.NoError(t, provider.AddScheme(auth.NewScheme("B", "cookie")))

	defaults := map[string]*auth.Scheme{
		"authenticate": provider.GetDefaultAuthenticateScheme(),
		"challenge":    provider.GetDefaultChallengeScheme(),
		"forbid":       provider.GetDefaultForbidScheme(),
		"signin":       provider.GetDefaultSignInScheme(),
		"signout":      provider.GetDefaultSignOutScheme(),
	}

	for category, scheme := range defaults {
		require.NotNilf(t, scheme, "category %q", category)
		require.Equalf(t, "B", scheme.Name, "category %q", category)
	}
}

func TestSchemeProviderSignOutFallsBackToSignInDefault(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider(&auth.Options{DefaultSignInScheme: "signin"})
	require.NoError(t, provider.AddScheme(auth.NewScheme("signin", "cookie")))
	require.NoError(t, provider.AddScheme(auth.NewScheme("unrelated", "cookie")))

	signOut := provider.GetDefaultSignOutScheme()
	require.NotNil(t, signOut)
	require.Equal(t, "signin", signOut.Name)
}

func TestSchemeProviderForbidFallsBackToChallengeDefault(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider(&auth.Options{DefaultChallengeScheme: "challenge"})
	require.NoError(t, provider.AddScheme(auth.NewScheme("challenge", "cookie")))
	require.NoError(t, provider.AddScheme(auth.NewScheme("unrelated", "cookie")))

	forbid := provider.GetDefaultForbidScheme()
	require.NotNil(t, forbid)
	require.Equal(t, "challenge", forbid.Name)
}

func TestSchemeProviderEachCategoryResolvesIndependently(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider(&auth.Options{
		DefaultScheme:             "Def",
		DefaultChallengeScheme:    "A",
		DefaultForbidScheme:       "B",
		DefaultSignInScheme:       "C",
		DefaultSignOutScheme:      "A",
		DefaultAuthenticateScheme: "C",
	})
	for _, name := range []string{"A", "B", "C", "Def"} {
		require.NoError(t, provider.AddScheme(auth.NewScheme(name, "cookie")))
	}

	wants := map[string]struct {
		got  *auth.Scheme
		name string
	}{
		"forbid":       {got: provider.GetDefaultForbidScheme(), name: "B"},
		"authenticate": {got: provider.GetDefaultAuthenticateScheme(), name: "C"},
		"challenge":    {got: provider.GetDefaultChallengeScheme(), name: "A"},
		"signin":       {got: provider.GetDefaultSignInScheme(), name: "C"},
		"signout":      {got: provider.GetDefaultSignOutScheme(), name: "A"},
	}
	for category, want := range wants {
		require.NotNilf(t, want.got, "category %q", category)
		require.Equalf(t, want.name, want.got.Name, "category %q", category)
	}
}

func TestSchemeProviderSignOutFallbackDoesNotCheckCapability(t *testing.T) {
	t.Parallel()

	// The registered sign-in scheme carries no sign-out capability marker; the
	// sign-out fallback resolves it regardless because wicket schemes declare no
	// capability and the fallback is unconditional.
	provider := NewSchemeProvider(&auth.Options{DefaultSignInScheme: "signin"})
	require.NoError(t, provider.AddScheme(auth.NewScheme("signin", "cookie")))

	require.NotNil(t, provider.GetDefaultSignOutScheme())
}

func TestSchemeProviderRemoveReleasesNameForReuse(t *testing.T) {
	t.Parallel()

	provider := NewSchemeProvider(auth.NewOptions())
	require.True(t, provider.TryAddScheme(auth.NewScheme("signin", "cookie")))
	require.True(t, provider.TryAddScheme(auth.NewScheme("signin2", "cookie")))

	// Removing a present name reports true; removing an absent name reports false.
	require.True(t, provider.RemoveScheme("signin2"))
	require.False(t, provider.RemoveScheme("absent"))

	// The released name can be registered again.
	require.True(t, provider.TryAddScheme(auth.NewScheme("signin2", "cookie")))
}
