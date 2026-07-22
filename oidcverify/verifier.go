// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package oidcverify

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/gonewx/wicket/services"
)

type Verifier interface {
	Verify(ctx context.Context, idToken string) (*VerifiedToken, error)
	VerifyWithNonce(ctx context.Context, idToken, nonce string) (*VerifiedToken, error)
}

type VerifiedToken struct {
	Subject       string
	Email         string
	EmailVerified bool
	Issuer        string
	Audience      []string
}

type ProviderConfig struct {
	Issuer        string
	Issuers       []string
	JWKSURI       string
	Audience      string
	Audiences     []string
	ClockSkew     time.Duration
	NonceRequired bool
}

func (c ProviderConfig) effectiveIssuers() []string {
	if len(c.Issuers) > 0 {
		return c.Issuers
	}
	if c.Issuer != "" {
		return []string{c.Issuer}
	}
	return nil
}

func (c ProviderConfig) effectiveAudiences() []string {
	if len(c.Audiences) > 0 {
		return c.Audiences
	}
	if c.Audience != "" {
		return []string{c.Audience}
	}
	return nil
}

type verifier struct {
	cache  *jwk.Cache
	config ProviderConfig
	clock  services.SystemClock
}

func NewVerifier(ctx context.Context, cfg ProviderConfig, clock services.SystemClock) (Verifier, error) {
	if len(cfg.effectiveIssuers()) == 0 {
		return nil, fmt.Errorf("oidcverify: at least one issuer must be configured")
	}
	if len(cfg.effectiveAudiences()) == 0 {
		return nil, fmt.Errorf("oidcverify: at least one audience must be configured")
	}

	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 5 * time.Minute
	}

	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, err
	}

	cache.Register(ctx, cfg.JWKSURI, jwk.WithMinInterval(15*time.Minute))

	return &verifier{
		cache:  cache,
		config: cfg,
		clock:  clock,
	}, nil
}
