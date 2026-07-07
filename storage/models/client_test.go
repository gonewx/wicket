// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"fmt"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/stretchr/testify/require"
)

// From: IdentityServer4/src/Storage/Models/Client.cs

func TestEmpty_should_be_allowed(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes([]string{})

	a.NoError(err)
}

func TestImplicit_should_be_allowed(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes(gois.GrantTypesImplicit)

	a.NoError(err)
}

func TestCustom_should_be_allowed(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes([]string{"custom"})

	a.NoError(err)
}

func TestCustom_should_be_allowed_raw(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes([]string{"custom"})

	a.NoError(err)
}

func TestForbidden_grant_type_combinations_should_throw(t *testing.T) {
	a := require.New(t)

	grantTypes1 := []string{gois.GrantTypeImplicit, gois.GrantTypeImplicit, gois.GrantTypeAuthorizationCode}
	grantTypes2 := []string{gois.GrantTypeHybrid, gois.GrantTypeAuthorizationCode, gois.GrantTypeHybrid}

	for i := range grantTypes1 {
		client := NewClient()
		err := client.SetAllowedGrantTypes([]string{grantTypes1[i], grantTypes2[i]})

		a.Error(err)
		a.Equal(fmt.Sprintf("Grant types list cannot contain both %s and %s", grantTypes1[i], grantTypes2[i]), err.Error())
	}

}

func TestCustom_and_forbidden_grant_type_combinations_should_throw(t *testing.T) {
	a := require.New(t)

	grantTypes1 := []string{gois.GrantTypeImplicit, gois.GrantTypeImplicit, gois.GrantTypeAuthorizationCode}
	grantTypes2 := []string{gois.GrantTypeHybrid, gois.GrantTypeAuthorizationCode, gois.GrantTypeHybrid}

	for i := range grantTypes1 {
		client := NewClient()
		err := client.SetAllowedGrantTypes([]string{"custom1", grantTypes1[i], "custom2", grantTypes2[i]})

		a.Error(err)
		a.Equal(fmt.Sprintf("Grant types list cannot contain both %s and %s", grantTypes1[i], grantTypes2[i]), err.Error())
	}

}

func TestDuplicate_values_should_throw(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes([]string{"custom1", "custom2", "custom1"})

	a.Error(err)
	a.Equal("Grant types list contains duplicate values", err.Error())
}

func TestNull_grant_type_list_should_throw_single(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes(nil)

	a.Error(err)
	a.Equal("Argument nil for grantTypes", err.Error())
}

func TestGrant_type_with_space_should_throw_single(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes([]string{"custo m2"})

	a.Error(err)
	a.Equal("Grant type cannot contain spaces", err.Error())
}

func TestGrant_type_with_space_should_throw_multiple(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes([]string{"custom1", "custo m2", "custom1"})

	a.Error(err)
	a.Equal("Grant type cannot contain spaces", err.Error())
}

func TestAdding_invalid_value_to_collection_should_throw(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes([]string{"implicit"})
	a.NoError(err)

	err = client.AddAllowedGrantTypes("authorization_code")

	a.Error(err)
	a.Equal("Grant types list cannot contain both implicit and authorization_code", err.Error())
}

func TestAdding_valid_value_to_collection_should_succeed(t *testing.T) {
	a := require.New(t)

	client := NewClient()
	err := client.SetAllowedGrantTypes([]string{"implicit"})
	a.NoError(err)

	err = client.AddAllowedGrantTypes("custom")

	a.NoError(err)
	a.Len(client.AllowedGrantTypes(), 2)
}
