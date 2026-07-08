// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"net/http"
)

type unsupportedEndpointHandler struct {
	name string
}

func (h *unsupportedEndpointHandler) Process(http.ResponseWriter, *http.Request) error {
	return fmt.Errorf("%s endpoint pending Epic 2/3 implementation", h.name)
}

type AuthorizeHandler struct{ unsupportedEndpointHandler }
type AuthorizeCallbackHandler struct{ unsupportedEndpointHandler }
type TokenHandler struct{ unsupportedEndpointHandler }
type DiscoveryHandler struct{ unsupportedEndpointHandler }
type DiscoveryKeyHandler struct{ unsupportedEndpointHandler }
type CheckSessionHandler struct{ unsupportedEndpointHandler }
type IntrospectionHandler struct{ unsupportedEndpointHandler }
type UserInfoHandler struct{ unsupportedEndpointHandler }
type EndSessionHandler struct{ unsupportedEndpointHandler }
type EndSessionCallbackHandler struct{ unsupportedEndpointHandler }

func NewAuthorizeHandler() *AuthorizeHandler {
	return &AuthorizeHandler{unsupportedEndpointHandler{name: "authorize"}}
}

func NewAuthorizeCallbackHandler() *AuthorizeCallbackHandler {
	return &AuthorizeCallbackHandler{unsupportedEndpointHandler{name: "authorize callback"}}
}

func NewTokenHandler() *TokenHandler {
	return &TokenHandler{unsupportedEndpointHandler{name: "token"}}
}

func NewDiscoveryHandler() *DiscoveryHandler {
	return &DiscoveryHandler{unsupportedEndpointHandler{name: "discovery"}}
}

func NewDiscoveryKeyHandler() *DiscoveryKeyHandler {
	return &DiscoveryKeyHandler{unsupportedEndpointHandler{name: "discovery keys"}}
}

func NewCheckSessionHandler() *CheckSessionHandler {
	return &CheckSessionHandler{unsupportedEndpointHandler{name: "check session"}}
}

func NewIntrospectionHandler() *IntrospectionHandler {
	return &IntrospectionHandler{unsupportedEndpointHandler{name: "introspection"}}
}

func NewUserInfoHandler() *UserInfoHandler {
	return &UserInfoHandler{unsupportedEndpointHandler{name: "userinfo"}}
}

func NewEndSessionHandler() *EndSessionHandler {
	return &EndSessionHandler{unsupportedEndpointHandler{name: "end session"}}
}

func NewEndSessionCallbackHandler() *EndSessionCallbackHandler {
	return &EndSessionCallbackHandler{unsupportedEndpointHandler{name: "end session callback"}}
}
