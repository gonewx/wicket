// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
)

func GetAuthenticationTime(principal wicket.Principal) time.Time {
	return time.Unix(GetAuthenticationTimeEpochFromPrincipal(principal), 0)
}

func GetAuthenticationTimeEpochFromPrincipal(principal wicket.Principal) int64 {
	if principal == nil {
		return 0
	}
	return GetAuthenticationTimeEpochFromIdentity(principal.Identity())
}

func GetAuthenticationTimeEpochFromIdentity(identity wicket.Identity) int64 {
	if identity == nil {
		return 0
	}
	i := identity.(*claimspkg.ClaimsIdentity)
	claim := i.FindFirst(wicket.JwtClaimTypesAuthenticationTime)

	if claim == nil {
		return 0
	}

	// golang 中， json unmarshal 后, any 类型默认是 float64
	if v, ok := claim.Value.(float64); ok {
		return int64(v)
	} else {
		if v, ok := claim.Value.(int64); ok {
			return v
		}
		return 0
	}
}

func GetSubjectIdFromPrincipal(principal wicket.Principal) string {
	if principal == nil {
		return ""
	}
	return GetSubjectIdFromIdentity(principal.Identity())
}

func GetSubjectIdFromIdentity(identity wicket.Identity) string {
	if identity == nil {
		return ""
	}
	i := identity.(*claimspkg.ClaimsIdentity)
	claim := i.FindFirst(wicket.JwtClaimTypesSubject)
	if claim == nil {
		return ""
	}
	return claim.Value.(string)
}

func GetIdentityProviderFromPrincipal(principal wicket.Principal) string {
	if principal == nil {
		return ""
	}
	return GetIdentityProviderFromIdentity(principal.Identity())
}

func GetIdentityProviderFromIdentity(identity wicket.Identity) string {
	if identity == nil {
		return ""
	}
	i := identity.(*claimspkg.ClaimsIdentity)
	claim := i.FindFirst(wicket.JwtClaimTypesIdentityProvider)

	if claim == nil {
		return ""
	}

	if v, ok := claim.Value.(string); ok {
		return v
	} else {
		return ""
	}
}

func ClaimsPrincipalIsAuthenticated(p wicket.Principal) bool {
	return p != nil && p.Identity() != nil && p.Identity().IsAuthenticated()
}

func GetAuthenticationMethodsByPrincipal(principal wicket.Principal) []*claimspkg.Claim {
	return GetAuthenticationMethodsByIdentity(principal.Identity())
}

func GetAuthenticationMethodsByIdentity(identity wicket.Identity) []*claimspkg.Claim {
	id := identity.(*claimspkg.ClaimsIdentity)
	return id.FindAll(wicket.JwtClaimTypesAuthenticationMethod)
}

func GetAuthenticationMethodByIdentity(identity wicket.Identity) string {
	id := identity.(*claimspkg.ClaimsIdentity)
	claim := id.FindFirst(wicket.JwtClaimTypesAuthenticationMethod)

	if claim == nil {
		return ""
	}

	return claim.Value.(string)
}

func GetTenantIdFromPrincipal(p *claimspkg.ClaimsPrincipal) string {
	cp := p.FindFirst(wicket.ClaimTypesTenant)
	if cp == nil {
		return ""
	}

	return cp.Value.(string)
}

func GetDisplayNameFromPrincipal(p *claimspkg.ClaimsPrincipal) string {
	if p == nil {
		return ""
	}

	name := p.Identity().Name()
	if name != "" {
		return name
	}

	sub := p.FindFirst(wicket.JwtClaimTypesSubject)
	if sub != nil {
		return sub.Value.(string)
	}

	return ""
}
