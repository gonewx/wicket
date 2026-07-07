// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import "github.com/gonewx/wicket"

// Convenience class that defines standard identity resources.
type IdentityResources struct {
}

// Models the standard openid scope
func IdentityResourcesOpenId() *IdentityResource {
	resource := NewIdentityResource()
	resource.Resource.Name = gois.StandardScopesOpenId
	resource.Resource.DisplayName = "Your user identifier"
	resource.Required = true
	resource.UserClaims = append(resource.UserClaims, gois.JwtClaimTypesSubject)

	return resource
}

// Models the standard profile scope
func IdentityResourcesProfile() *IdentityResource {
	resource := NewIdentityResource()

	resource.Resource.Name = gois.StandardScopesProfile
	resource.Resource.DisplayName = "User profile"
	resource.Resource.Description = "Your user profile information (first name, last name, etc.)"
	resource.Emphasize = true
	resource.UserClaims = gois.ScopeToClaimsMapping[gois.StandardScopesProfile]

	return resource
}

// Models the standard email scope

func IdentityResourcesEmail() *IdentityResource {
	resource := NewIdentityResource()

	resource.Resource.Name = gois.StandardScopesEmail
	resource.Resource.DisplayName = "Your email address"
	resource.Emphasize = true
	resource.UserClaims = gois.ScopeToClaimsMapping[gois.StandardScopesEmail]

	return resource
}

// Models the standard phone scope
func IdentityResourcesPhone() *IdentityResource {
	resource := NewIdentityResource()

	resource.Resource.Name = gois.StandardScopesPhone
	resource.Resource.DisplayName = "Your phone number"
	resource.Emphasize = true
	resource.UserClaims = append(resource.UserClaims, gois.StandardScopesPhone)

	return resource
}

// Models the standard address scope
func IdentityResourcesAddress() *IdentityResource {
	resource := NewIdentityResource()

	resource.Resource.Name = gois.StandardScopesAddress
	resource.Resource.DisplayName = "Your postal addressuser identifier"
	resource.Emphasize = true
	resource.UserClaims = append(resource.UserClaims, gois.StandardScopesAddress)

	return resource
}
