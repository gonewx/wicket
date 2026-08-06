// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gonewx/wicket/auth"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/services"
)

// restoreClaimValue maps a json.Number back onto the numeric type the claim
// carried before serialization: integral values return as int64, fractional
// ones as float64. Typed claim consumers (for example the authentication-time
// epoch) then see the same dynamic type across the cookie round-trip.
func restoreClaimValue(v any) any {
	number, ok := v.(json.Number)
	if !ok {
		return v
	}
	if i, err := number.Int64(); err == nil {
		return i
	}
	if f, err := number.Float64(); err == nil {
		return f
	}
	return number.String()
}

var _ auth.Handler = (*testCookieAuthenticationHandler)(nil)
var _ auth.SignInHandler = (*testCookieAuthenticationHandler)(nil)
var _ auth.SignOutHandler = (*testCookieAuthenticationHandler)(nil)

// testCookieAuthenticationHandler is a host-side cookie authentication handler
// for the integration pipeline. It keeps the authentication ticket in a single
// HttpOnly cookie named after the scheme: SignIn serializes the principal and
// properties into the cookie and establishes the server-side session;
// Authenticate restores the ticket from the cookie. The payload is plain
// base64-encoded JSON — the handler simulates the hosting environment for
// tests and does not provide production-grade ticket protection.
type testCookieAuthenticationHandler struct {
	request     *http.Request
	response    http.ResponseWriter
	scheme      *auth.Scheme
	userSession services.UserSession
}

func newTestCookieAuthenticationHandler(userSession services.UserSession) *testCookieAuthenticationHandler {
	return &testCookieAuthenticationHandler{userSession: userSession}
}

type ticketClaim struct {
	Type           string `json:"type"`
	Value          any    `json:"value"`
	ValueType      string `json:"valueType,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	OriginalIssuer string `json:"originalIssuer,omitempty"`
}

type ticketIdentity struct {
	AuthenticationType string        `json:"authenticationType"`
	NameClaimType      string        `json:"nameClaimType,omitempty"`
	RoleClaimType      string        `json:"roleClaimType,omitempty"`
	Claims             []ticketClaim `json:"claims"`
}

type ticket struct {
	Identities []ticketIdentity  `json:"identities"`
	Items      map[string]string `json:"items,omitempty"`
}

func (h *testCookieAuthenticationHandler) Initialize(request *http.Request, response http.ResponseWriter, scheme *auth.Scheme) error {
	h.request = request
	h.response = response
	h.scheme = scheme
	return nil
}

func (h *testCookieAuthenticationHandler) cookieName() string {
	if h.scheme != nil && h.scheme.Name != "" {
		return h.scheme.Name
	}
	return ""
}

func (h *testCookieAuthenticationHandler) Authenticate() (*auth.Result, error) {
	if h.request == nil {
		return auth.NoResult(), nil
	}
	name := h.cookieName()
	if name == "" {
		return auth.NoResult(), nil
	}
	cookie, err := h.request.Cookie(name)
	if err != nil || cookie.Value == "" {
		return auth.NoResult(), nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return auth.NoResult(), nil
	}
	var t ticket
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Numbers decode as json.Number so integral claim values can be restored
	// to the type they were signed in with instead of widening to float64.
	decoder.UseNumber()
	if err := decoder.Decode(&t); err != nil {
		return auth.NoResult(), nil
	}

	principal := claimspkg.NewClaimsPrincipal()
	for _, id := range t.Identities {
		identity := claimspkg.NewClaimsIdentity(
			claimspkg.WithAuthenticationType(id.AuthenticationType),
			claimspkg.WithNameClaimType(id.NameClaimType),
			claimspkg.WithRoleClaimType(id.RoleClaimType),
		)
		for _, c := range id.Claims {
			identity.AddClaim(&claimspkg.Claim{
				Type:           c.Type,
				Value:          restoreClaimValue(c.Value),
				ValueType:      c.ValueType,
				Issuer:         c.Issuer,
				OriginalIssuer: c.OriginalIssuer,
			})
		}
		principal.Identities = append(principal.Identities, identity)
	}

	properties := auth.NewProperties()
	for k, v := range t.Items {
		properties.Items[k] = v
	}
	return &auth.Result{Principal: principal, Properties: properties}, nil
}

func (h *testCookieAuthenticationHandler) SignIn(user *claimspkg.ClaimsPrincipal, properties *auth.Properties) error {
	if h.response == nil {
		return fmt.Errorf("sign-in requires a response writer")
	}
	name := h.cookieName()
	if name == "" {
		return fmt.Errorf("sign-in requires a scheme name")
	}

	t := ticket{Items: map[string]string{}}
	if user != nil {
		for _, id := range user.Identities {
			ti := ticketIdentity{
				AuthenticationType: id.AuthenticationType(),
				NameClaimType:      id.NameClaimType,
				RoleClaimType:      id.RoleClaimType,
			}
			for _, c := range id.Claims() {
				if c == nil {
					continue
				}
				ti.Claims = append(ti.Claims, ticketClaim{
					Type:           c.Type,
					Value:          c.Value,
					ValueType:      c.ValueType,
					Issuer:         c.Issuer,
					OriginalIssuer: c.OriginalIssuer,
				})
			}
			t.Identities = append(t.Identities, ti)
		}
	}
	if properties != nil {
		for k, v := range properties.Items {
			t.Items[k] = v
		}
	}

	raw, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("serialize ticket: %w", err)
	}
	http.SetCookie(h.response, &http.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		HttpOnly: true,
		Path:     "/",
	})

	if h.userSession != nil {
		if _, err := h.userSession.CreateSessionId(h.request.Context(), user, properties); err != nil {
			return fmt.Errorf("create session: %w", err)
		}
	}
	return nil
}

func (h *testCookieAuthenticationHandler) SignOut(properties *auth.Properties) error {
	if h.response == nil {
		return nil
	}
	name := h.cookieName()
	if name == "" {
		return nil
	}
	http.SetCookie(h.response, &http.Cookie{
		Name:     name,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
	})
	return nil
}

func (h *testCookieAuthenticationHandler) Challenge(properties *auth.Properties) error {
	return nil
}

func (h *testCookieAuthenticationHandler) Forbid(properties *auth.Properties) error {
	return nil
}
