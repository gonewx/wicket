// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package setup

import (
	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/test"
)

func GetUsers() []*test.TestUser {

	user1 := test.NewTestUser()
	user1.SubjectId = "818727"
	user1.Username = "alice"
	user1.Password = "alice"
	user1.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesName), claimspkg.WithClaimValue("Alice Smith"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesGivenName), claimspkg.WithClaimValue("Alice"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesFamilyName), claimspkg.WithClaimValue("Smith"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesEmail), claimspkg.WithClaimValue("AliceSmith@email.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesEmailVerified), claimspkg.WithClaimValue(true),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesRole), claimspkg.WithClaimValue("Admin"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesRole), claimspkg.WithClaimValue("Geek"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesWebSite), claimspkg.WithClaimValue("http://alice.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesAddress), claimspkg.WithClaimValue("{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }"),
		),
	}

	user2 := test.NewTestUser()
	user2.SubjectId = "88421113"
	user2.Username = "bob"
	user2.Password = "bob"
	user2.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesName), claimspkg.WithClaimValue("Bob Smith"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesGivenName), claimspkg.WithClaimValue("Bob"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesFamilyName), claimspkg.WithClaimValue("Smith"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesEmail), claimspkg.WithClaimValue("BobSmith@email.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesEmailVerified), claimspkg.WithClaimValue(true),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesRole), claimspkg.WithClaimValue("Developer"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesRole), claimspkg.WithClaimValue("Geek"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesWebSite), claimspkg.WithClaimValue("http://bob.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesAddress), claimspkg.WithClaimValue("{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }"),
		),
	}

	user3 := test.NewTestUser()
	user3.SubjectId = "88421113"
	user3.Username = "bob_no_password"
	user3.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesName), claimspkg.WithClaimValue("Bob Smith"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesGivenName), claimspkg.WithClaimValue("Bob"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesFamilyName), claimspkg.WithClaimValue("Smith"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesEmail), claimspkg.WithClaimValue("BobSmith@email.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesEmailVerified), claimspkg.WithClaimValue(true),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesRole), claimspkg.WithClaimValue("Developer"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesRole), claimspkg.WithClaimValue("Geek"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesWebSite), claimspkg.WithClaimValue("http://bob.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesAddress), claimspkg.WithClaimValue("{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }"),
		),
	}

	return []*test.TestUser{user1, user2, user3}
}
