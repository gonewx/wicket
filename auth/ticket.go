// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package auth

import "github.com/gonewx/wicket/claims"

type Ticket struct {
	Scheme     string
	Principal  *claims.ClaimsPrincipal
	Properties *Properties
}

func NewTicket(principal *claims.ClaimsPrincipal, scheme string, properties *Properties) *Ticket {
	if properties == nil {
		properties = NewProperties()
	}
	return &Ticket{
		Scheme:     scheme,
		Principal:  principal,
		Properties: properties,
	}
}

func (t *Ticket) Clone() *Ticket {
	principal := claims.NewClaimsPrincipal()
	for _, identity := range t.Principal.Identities {
		principal.Identities = append(principal.Identities, identity.Clone())
	}
	return NewTicket(principal, t.Scheme, t.Properties.Clone())
}
