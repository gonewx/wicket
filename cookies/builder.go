// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package cookies

import (
	"net/http"
	"time"
)

type CookieSecurePolicy int

const (
	CookieSecurePolicySameAsRequest CookieSecurePolicy = iota
	CookieSecurePolicyAlways
	CookieSecurePolicyNone
)

// Clock is an injectable time source. A builder with no clock set falls back to
// the wall clock, so a zero-value builder stays usable and cookie expiry becomes
// testable under a fixed clock.
type Clock interface {
	Now() time.Time
}

type Options struct {
	Domain      string
	Path        string
	Expires     *time.Time
	Secure      bool
	SameSite    http.SameSite
	HttpOnly    bool
	MaxAge      *time.Duration
	IsEssential bool
}

type Builder interface {
	Name() string
	SetName(name string)
	Path() string
	SetPath(path string)
	SameSite() http.SameSite
	SetSameSite(sameSite http.SameSite)
	SecurePolicy() CookieSecurePolicy
	SetSecurePolicy(policy CookieSecurePolicy)
	IsEssential() bool
	SetIsEssential(isEssential bool)
	SetClock(clock Clock)
	Build(req *http.Request) *Options
	BuildWithExpires(req *http.Request, expiresFrom time.Time) *Options
}

type BaseBuilder struct {
	name         string
	path         string
	Domain       string
	HttpOnly     bool
	sameSite     http.SameSite
	securePolicy CookieSecurePolicy
	Expiration   *time.Duration
	MaxAge       *time.Duration
	isEssential  bool
	clock        Clock
}

func NewBaseBuilder() *BaseBuilder {
	return &BaseBuilder{
		sameSite: http.SameSiteDefaultMode,
	}
}

func (b *BaseBuilder) Name() string                              { return b.name }
func (b *BaseBuilder) SetName(name string)                       { b.name = name }
func (b *BaseBuilder) Path() string                              { return b.path }
func (b *BaseBuilder) SetPath(path string)                       { b.path = path }
func (b *BaseBuilder) SameSite() http.SameSite                   { return b.sameSite }
func (b *BaseBuilder) SetSameSite(sameSite http.SameSite)        { b.sameSite = sameSite }
func (b *BaseBuilder) SecurePolicy() CookieSecurePolicy          { return b.securePolicy }
func (b *BaseBuilder) SetSecurePolicy(policy CookieSecurePolicy) { b.securePolicy = policy }
func (b *BaseBuilder) IsEssential() bool                         { return b.isEssential }
func (b *BaseBuilder) SetIsEssential(isEssential bool)           { b.isEssential = isEssential }
func (b *BaseBuilder) SetClock(clock Clock)                      { b.clock = clock }

// Now reports the build-stamp time from the injected clock, falling back to the
// wall clock when none is set. Overriding builders reuse it through embedding so
// cookie expiry stays testable under a fixed clock.
func (b *BaseBuilder) Now() time.Time {
	if b.clock != nil {
		return b.clock.Now()
	}
	return time.Now()
}

func (b *BaseBuilder) Build(req *http.Request) *Options {
	return b.BuildWithExpires(req, b.Now())
}

func (b *BaseBuilder) BuildWithExpires(req *http.Request, expiresFrom time.Time) *Options {
	var expires *time.Time
	if b.Expiration != nil {
		e := expiresFrom.Add(*b.Expiration)
		expires = &e
	}
	path := "/"
	if b.path != "" {
		path = b.path
	}
	return &Options{
		Path:        path,
		SameSite:    b.sameSite,
		HttpOnly:    b.HttpOnly,
		MaxAge:      b.MaxAge,
		Domain:      b.Domain,
		IsEssential: b.isEssential,
		Secure:      b.securePolicy == CookieSecurePolicyAlways || (b.securePolicy == CookieSecurePolicySameAsRequest && req.TLS != nil),
		Expires:     expires,
	}
}
