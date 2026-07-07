// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package cookies

import (
	"net/http"
	"time"

	"github.com/gonewx/wicket/dp"
)

type CookieBuilder struct {
	Name        string
	IsEssential bool
	SameSite    http.SameSite
}

func (c *CookieBuilder) SetName(value string) {
	c.Name = value
}

func (c *CookieBuilder) SetIsEssential(value bool) {
	c.IsEssential = value
}

func (c *CookieBuilder) SetSameSite(value http.SameSite) {
	c.SameSite = value
}

type AuthenticationOptions struct {
	SlidingExpiration  bool
	ExpireTimeSpan     time.Duration
	LoginPath          string
	LogoutPath         string
	ReturnUrlParameter string
	cookie             *CookieBuilder
}

func NewAuthenticationOptions() *AuthenticationOptions {
	return &AuthenticationOptions{
		ReturnUrlParameter: "returnUrl",
		cookie:             &CookieBuilder{},
	}
}

func (o *AuthenticationOptions) New() *AuthenticationOptions {
	return NewAuthenticationOptions()
}

func (o *AuthenticationOptions) Cookie() *CookieBuilder {
	if o.cookie == nil {
		o.cookie = &CookieBuilder{}
	}
	return o.cookie
}

func (o *AuthenticationOptions) Validate() error {
	return nil
}

type PostConfigureAuthenticationOptions struct {
	provider dp.DataProtectionProvider
}

func NewPostConfigureAuthenticationOptions(provider dp.DataProtectionProvider) *PostConfigureAuthenticationOptions {
	return &PostConfigureAuthenticationOptions{provider: provider}
}

func (p *PostConfigureAuthenticationOptions) PostConfigure(name string, options *AuthenticationOptions) error {
	if options != nil {
		options.Cookie()
	}
	return nil
}
