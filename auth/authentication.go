// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package auth

import (
	"net/http"

	"github.com/gonewx/wicket/claims"
)

// Properties carries authentication state across a request. It holds two layers
// of data with distinct persistence rules: Items (string keyed strings) is the
// serializable, cross-request layer, while parameters is an in-process-only
// layer that is never serialized. Typed properties (persistence, redirect,
// issued/expires timestamps, refresh) are not separate fields; they are encoded
// as reserved-key entries inside Items.
type Properties struct {
	Items      map[string]string
	parameters map[string]any
}

func NewProperties() *Properties {
	return &Properties{
		Items:      map[string]string{},
		parameters: map[string]any{},
	}
}

func (p *Properties) GetTokens() []*Token {
	if p == nil || p.Items == nil {
		return nil
	}
	return nil
}

type Result struct {
	Ticket     *Ticket
	Principal  *claims.ClaimsPrincipal
	Properties *Properties
	Failure    error
	None       bool
}

func (r *Result) Succeeded() bool {
	return r != nil && r.Ticket != nil
}

func NoResult() *Result {
	return &Result{None: true}
}

type Scheme struct {
	Name        string
	HandlerType string
	// HandlesRequests marks a scheme whose handler participates in request
	// processing (for example a remote callback), so the middleware can
	// enumerate it ahead of the default authentication pass.
	HandlesRequests bool
}

func NewScheme(name string, handlerType string) *Scheme {
	return &Scheme{Name: name, HandlerType: handlerType}
}

// NewRequestHandlerScheme builds a scheme whose handler participates in request
// processing — an external identity provider callback, for instance — so the
// middleware enumerates it ahead of the default authenticate pass. It sets the
// request-handling capability that the dynamic subsystem assigns to its runtime
// provider schemes, giving static registrations the same standing.
func NewRequestHandlerScheme(name string, handlerType string) *Scheme {
	return &Scheme{Name: name, HandlerType: handlerType, HandlesRequests: true}
}

type Options struct {
	DefaultScheme             string
	DefaultAuthenticateScheme string
	DefaultChallengeScheme    string
	DefaultForbidScheme       string
	DefaultSignInScheme       string
	DefaultSignOutScheme      string
}

func NewOptions() *Options {
	return &Options{}
}

func (o *Options) New() *Options {
	return NewOptions()
}

type Service interface {
	Authenticate(*http.Request, http.ResponseWriter, string) (*Result, error)
	Challenge(*http.Request, http.ResponseWriter, string, *Properties) error
	Forbid(*http.Request, http.ResponseWriter, string, *Properties) error
	SignIn(*http.Request, http.ResponseWriter, string, *claims.ClaimsPrincipal, *Properties) error
	SignOut(*http.Request, http.ResponseWriter, string, *Properties) error
}

type Handler interface {
	Initialize(*http.Request, http.ResponseWriter, *Scheme) error
	Authenticate() (*Result, error)
	Challenge(*Properties) error
	Forbid(*Properties) error
}

type SignInHandler interface {
	Handler
	SignIn(*claims.ClaimsPrincipal, *Properties) error
}

type SignOutHandler interface {
	Handler
	SignOut(*Properties) error
}

// RequestHandler is a handler that can claim a request and process it before the
// default authentication pass — a remote callback endpoint being the canonical
// case. The middleware asks ShouldHandleRequest whether the handler owns the
// current request, then drives HandleRequest, whose bool reports whether the
// response was written (handled) and the pipeline should short-circuit.
type RequestHandler interface {
	Handler
	ShouldHandleRequest() bool
	HandleRequest() (bool, error)
}

type HandlerProvider interface {
	GetHandler(*http.Request, http.ResponseWriter, string) (Handler, error)
}

type SchemeProvider interface {
	GetAllSchemes() []*Scheme
	GetScheme(string) *Scheme
	GetDefaultAuthenticateScheme() *Scheme
	GetDefaultChallengeScheme() *Scheme
	GetDefaultForbidScheme() *Scheme
	GetDefaultSignInScheme() *Scheme
	GetDefaultSignOutScheme() *Scheme
	AddScheme(*Scheme) error
	TryAddScheme(*Scheme) bool
	RemoveScheme(string) bool
	GetRequestHandlerSchemes() ([]*Scheme, error)
}

type ClaimsTransformation interface {
	Transform(*claims.ClaimsPrincipal) (*claims.ClaimsPrincipal, error)
}
