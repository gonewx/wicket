// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package claims

import gois "github.com/gonewx/wicket"

const DefaultIssuer = "LOCAL AUTHORITY"

const Name = "name"

type Claim struct {
	Type           string
	Value          any
	ValueType      string
	Issuer         string
	OriginalIssuer string
}

type ClaimOption func(*Claim)

func NewClaim(opts ...ClaimOption) *Claim {
	c := &Claim{Issuer: DefaultIssuer, OriginalIssuer: DefaultIssuer}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func WithClaimType(value string) ClaimOption {
	return func(c *Claim) { c.Type = value }
}

func WithClaimValue(value any) ClaimOption {
	return func(c *Claim) { c.Value = value }
}

func WithClaimValueType(value string) ClaimOption {
	return func(c *Claim) { c.ValueType = value }
}

func WithClaimIssuer(value string) ClaimOption {
	return func(c *Claim) { c.Issuer = value }
}

func WithClaimOriginalIssuer(value string) ClaimOption {
	return func(c *Claim) { c.OriginalIssuer = value }
}

type ClaimComparer struct{}

func NewClaimComparer() ClaimComparer {
	return ClaimComparer{}
}

func (ClaimComparer) Equal(a, b *Claim) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Type == b.Type && a.Value == b.Value && a.Issuer == b.Issuer
}

type ClaimsIdentity struct {
	authenticationType string
	NameClaimType      string
	RoleClaimType      string
	claims             []*Claim
}

type ClaimsIdentityOption func(*ClaimsIdentity)

func NewClaimsIdentity(opts ...ClaimsIdentityOption) *ClaimsIdentity {
	i := &ClaimsIdentity{}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

func WithAuthenticationType(value string) ClaimsIdentityOption {
	return func(i *ClaimsIdentity) { i.authenticationType = value }
}

func WithNameClaimType(value string) ClaimsIdentityOption {
	return func(i *ClaimsIdentity) { i.NameClaimType = value }
}

func WithRoleClaimType(value string) ClaimsIdentityOption {
	return func(i *ClaimsIdentity) { i.RoleClaimType = value }
}

func WithClaims(claims []*Claim) ClaimsIdentityOption {
	return func(i *ClaimsIdentity) { i.claims = append(i.claims, claims...) }
}

func (i *ClaimsIdentity) AddClaim(claim *Claim) {
	i.claims = append(i.claims, claim)
}

func (i *ClaimsIdentity) Claims() []*Claim {
	if i == nil {
		return nil
	}
	return i.claims
}

func (i *ClaimsIdentity) IsAuthenticated() bool {
	return i != nil && i.authenticationType != ""
}

func (i *ClaimsIdentity) AuthenticationType() string {
	if i == nil {
		return ""
	}
	return i.authenticationType
}

func (i *ClaimsIdentity) Name() string {
	if i == nil {
		return ""
	}
	claimType := i.NameClaimType
	if claimType == "" {
		claimType = "name"
	}
	claim := i.FindFirst(claimType)
	if claim == nil {
		return ""
	}
	value, _ := claim.Value.(string)
	return value
}

func (i *ClaimsIdentity) FindFirst(claimType string) *Claim {
	if i == nil {
		return nil
	}
	for _, claim := range i.claims {
		if claim != nil && claim.Type == claimType {
			return claim
		}
	}
	return nil
}

func (i *ClaimsIdentity) FindAll(claimType string) []*Claim {
	if i == nil {
		return nil
	}
	out := make([]*Claim, 0)
	for _, claim := range i.claims {
		if claim != nil && claim.Type == claimType {
			out = append(out, claim)
		}
	}
	return out
}

type ClaimsPrincipal struct {
	Identities []*ClaimsIdentity
}

type ClaimsPrincipalOption func(*ClaimsPrincipal)

func NewClaimsPrincipal(opts ...ClaimsPrincipalOption) *ClaimsPrincipal {
	p := &ClaimsPrincipal{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func ClaimsPrincipalAnonymous() *ClaimsPrincipal {
	return NewClaimsPrincipal()
}

func WithClaimsPrincipalIdentity(identity *ClaimsIdentity) ClaimsPrincipalOption {
	return func(p *ClaimsPrincipal) {
		if identity != nil {
			p.Identities = append(p.Identities, identity)
		}
	}
}

func (p *ClaimsPrincipal) Claims() []*Claim {
	if p == nil {
		return nil
	}
	claims := make([]*Claim, 0)
	for _, identity := range p.Identities {
		claims = append(claims, identity.Claims()...)
	}
	return claims
}

func (p *ClaimsPrincipal) Identity() gois.Identity {
	if p == nil || len(p.Identities) == 0 {
		return nil
	}
	return p.Identities[0]
}

func (p *ClaimsPrincipal) FindFirst(claimType string) *Claim {
	if p == nil {
		return nil
	}
	for _, identity := range p.Identities {
		if claim := identity.FindFirst(claimType); claim != nil {
			return claim
		}
	}
	return nil
}

func (p *ClaimsPrincipal) FindAll(claimType string) []*Claim {
	if p == nil {
		return nil
	}
	out := make([]*Claim, 0)
	for _, identity := range p.Identities {
		out = append(out, identity.FindAll(claimType)...)
	}
	return out
}
