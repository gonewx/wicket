// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
)

func GetAuthenticationTime(principal gois.Principal) time.Time {
	return time.Unix(GetAuthenticationTimeEpochFromPrincipal(principal), 0)
}

func GetAuthenticationTimeEpochFromPrincipal(principal gois.Principal) int64 {
	if principal == nil {
		return 0
	}
	return GetAuthenticationTimeEpochFromIdentity(principal.Identity())
}

func GetAuthenticationTimeEpochFromIdentity(identity gois.Identity) int64 {
	if identity == nil {
		return 0
	}
	i := identity.(*claimspkg.ClaimsIdentity)
	claim := i.FindFirst(gois.JwtClaimTypesAuthenticationTime)

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

func GetSubjectIdFromPrincipal(principal gois.Principal) string {
	if principal == nil {
		return ""
	}
	return GetSubjectIdFromIdentity(principal.Identity())
}

func GetSubjectIdFromIdentity(identity gois.Identity) string {
	if identity == nil {
		return ""
	}
	i := identity.(*claimspkg.ClaimsIdentity)
	claim := i.FindFirst(gois.JwtClaimTypesSubject)
	if claim == nil {
		return ""
	}
	return claim.Value.(string)
}

func GetIdentityProviderFromPrincipal(principal gois.Principal) string {
	if principal == nil {
		return ""
	}
	return GetIdentityProviderFromIdentity(principal.Identity())
}

func GetIdentityProviderFromIdentity(identity gois.Identity) string {
	if identity == nil {
		return ""
	}
	i := identity.(*claimspkg.ClaimsIdentity)
	claim := i.FindFirst(gois.JwtClaimTypesIdentityProvider)

	if claim == nil {
		return ""
	}

	if v, ok := claim.Value.(string); ok {
		return v
	} else {
		return ""
	}
}

func ClaimsPrincipalIsAuthenticated(p gois.Principal) bool {
	return p != nil && p.Identity() != nil && p.Identity().IsAuthenticated()
}

func GetAuthenticationMethodsByPrincipal(principal gois.Principal) []*claimspkg.Claim {
	return GetAuthenticationMethodsByIdentity(principal.Identity())
}

func GetAuthenticationMethodsByIdentity(identity gois.Identity) []*claimspkg.Claim {
	id := identity.(*claimspkg.ClaimsIdentity)
	return id.FindAll(gois.JwtClaimTypesAuthenticationMethod)
}

func GetAuthenticationMethodByIdentity(identity gois.Identity) string {
	id := identity.(*claimspkg.ClaimsIdentity)
	claim := id.FindFirst(gois.JwtClaimTypesAuthenticationMethod)

	if claim == nil {
		return ""
	}

	return claim.Value.(string)
}

func GetTenantIdFromPrincipal(p *claimspkg.ClaimsPrincipal) string {
	cp := p.FindFirst(gois.ClaimTypesTenant)
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

	sub := p.FindFirst(gois.JwtClaimTypesSubject)
	if sub != nil {
		return sub.Value.(string)
	}

	return ""
}
