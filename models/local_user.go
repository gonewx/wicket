// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/utils"
)

type LocalUser struct {
	SubjectId             string
	DisplayName           string
	IdentityProvider      string
	Tenant                string
	AuthenticationMethods []string
	AuthenticationTime    *time.Time
	AdditionalClaims      []*claimspkg.Claim
}

func WithLocalUserSubjectId(subjectId string) wicket.Option[LocalUser] {
	return func(u *LocalUser) {
		u.SubjectId = subjectId
	}
}
func NewLocalUser(opts ...wicket.Option[LocalUser]) *LocalUser {
	i := &LocalUser{}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

func (u *LocalUser) CreatePrincipal() (*claimspkg.ClaimsPrincipal, error) {
	if u.SubjectId == "" {
		return nil, fmt.Errorf("SubjectId is mandatory")
	}

	claims := make([]*claimspkg.Claim, 0)
	claims = append(claims, &claimspkg.Claim{Type: wicket.JwtClaimTypesSubject, Value: u.SubjectId})

	if strings.TrimSpace(u.DisplayName) != "" {
		claims = append(claims, &claimspkg.Claim{Type: wicket.JwtClaimTypesName, Value: u.DisplayName})
	}

	if strings.TrimSpace(u.IdentityProvider) != "" {
		claims = append(claims, &claimspkg.Claim{Type: wicket.JwtClaimTypesIdentityProvider, Value: u.IdentityProvider})
	}

	if strings.TrimSpace(u.Tenant) != "" {
		claims = append(claims, &claimspkg.Claim{Type: wicket.ClaimTypesTenant, Value: u.Tenant})
	}

	if u.AuthenticationTime != nil {
		claims = append(claims, &claimspkg.Claim{Type: wicket.JwtClaimTypesAuthenticationTime, Value: u.AuthenticationTime.Unix()})
	}

	if utils.Any(u.AuthenticationMethods) {
		for _, amr := range u.AuthenticationMethods {
			claims = append(claims, &claimspkg.Claim{Type: wicket.JwtClaimTypesAuthenticationMethod, Value: amr})

		}

	}

	claims = append(claims, u.AdditionalClaims...)

	claims = utils.DistinctEq[*claimspkg.Claim](claims, claimspkg.NewClaimComparer())

	id := claimspkg.NewClaimsIdentity(
		claimspkg.WithClaims(claims),
		claimspkg.WithAuthenticationType(wicket.WicketAuthenticationType),
		claimspkg.WithNameClaimType(wicket.JwtClaimTypesName),
		claimspkg.WithRoleClaimType(wicket.JwtClaimTypesRole),
	)
	return claimspkg.NewClaimsPrincipal(claimspkg.WithClaimsPrincipalIdentity(id)), nil
}
