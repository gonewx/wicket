// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package test

import (
	"strings"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	tokjwt "github.com/gonewx/wicket/tokens/jwt"
	"github.com/gonewx/wicket/utils"
)

// TestUserStore Store for test users
type TestUserStore struct {
	users []*TestUser
}

func NewTestUserStore(users []*TestUser) *TestUserStore {
	return &TestUserStore{
		users: users,
	}
}

// ValidateCredentials Validates the credentials.
func (s *TestUserStore) ValidateCredentials(username string, password string) bool {
	var user = s.FindByUsername(username)
	if user != nil {
		if strings.TrimSpace(user.Password) == "" && strings.TrimSpace(password) == "" {
			return true
		}
		return user.Password == password
	}
	return false
}

// FindBySubjectId finds the user by subject identifier.
func (t *TestUserStore) FindBySubjectId(subjectId string) *TestUser {
	for _, user := range t.users {
		if user.SubjectId == subjectId {
			return user
		}
	}
	return nil
}

// FindByUsername finds the user by username.
func (t *TestUserStore) FindByUsername(username string) *TestUser {
	for _, user := range t.users {
		if strings.EqualFold(user.Username, username) {
			return user
		}
	}
	return nil
}

// FindByExternalProvider finds the user by external provider.
func (t *TestUserStore) FindByExternalProvider(provider, userId string) *TestUser {
	for _, user := range t.users {
		if user.ProviderName == provider && user.ProviderSubjectId == userId {
			return user
		}
	}
	return nil
}

// AutoProvisionUser automatically provisions a user.
func (t *TestUserStore) AutoProvisionUser(provider, userId string, claims []*claimspkg.Claim) *TestUser {
	// create a list of claims that we want to transfer into our store
	filtered := []*claimspkg.Claim{}

	// if the external system sends a display name - translate that to the standard OIDC name claim
	// if the JWT handler has an outbound mapping to an OIDC claim use that
	// copy the claim as-is
	for _, claim := range claims {
		if claim.Type == claimspkg.Name {
			filtered = append(filtered,
				claimspkg.NewClaim(
					claimspkg.WithClaimType(wicket.JwtClaimTypesName),
					claimspkg.WithClaimValue(claim.Value),
				),
			)

		} else {
			// if the JWT handler has an outbound mapping to an OIDC claim use that
			claimType, ok := tokjwt.OutboundClaimTypeMap()[claim.Type]
			if ok {
				filtered = append(filtered, claimspkg.NewClaim(
					claimspkg.WithClaimType(claimType),
					claimspkg.WithClaimValue(claim.Value),
				))
			} else {
				// copy the claim as-is
				filtered = append(filtered, claim)
			}
		}
	}

	// if no display name was provided, try to construct by first and/or last name
	if !utils.AnyPred(filtered, func(x *claimspkg.Claim) bool {
		return x.Type == wicket.JwtClaimTypesName
	}) {
		var first, last string
		v := utils.FirstOrDefaultPred(filtered, func(x *claimspkg.Claim) bool {
			return x.Type == wicket.JwtClaimTypesGivenName
		})
		if v != nil {
			first = v.Value.(string)
		}
		v = utils.FirstOrDefaultPred(filtered, func(x *claimspkg.Claim) bool {
			return x.Type == wicket.JwtClaimTypesFamilyName
		})
		if v != nil {
			last = v.Value.(string)
		}
		if first != "" && last != "" {
			filtered = append(filtered, claimspkg.NewClaim(
				claimspkg.WithClaimType(wicket.JwtClaimTypesName),
				claimspkg.WithClaimValue(first+" "+last),
			),
			)
		} else if first != "" {
			filtered = append(filtered, claimspkg.NewClaim(
				claimspkg.WithClaimType(wicket.JwtClaimTypesName),
				claimspkg.WithClaimValue(first),
			))
		} else if last != "" {
			filtered = append(filtered, claimspkg.NewClaim(
				claimspkg.WithClaimType(wicket.JwtClaimTypesName),
				claimspkg.WithClaimValue(last),
			))
		}
	}

	// create a new unique subject id
	// var sub = CryptoRandom.CreateUniqueId(format: CryptoRandom.OutputFormat.Hex)
	sub, err := utils.CreateUniqueId(32, utils.Hex)
	if err != nil {
		panic(err)
	}
	// check if a display name is available, otherwise fallback to subject id
	v := utils.FirstOrDefaultPred(filtered, func(x *claimspkg.Claim) bool {
		return x.Type == wicket.JwtClaimTypesName
	})

	name := ""
	if v != nil {
		name = v.Value.(string)
	}
	if name == "" {
		name = sub
	}
	// create new user
	user := NewTestUser()
	user.SubjectId = sub
	user.Username = name
	user.ProviderName = provider
	user.ProviderSubjectId = userId
	user.Claims = filtered

	// add user to in-memory store
	t.users = append(t.users, user)

	return user
}
