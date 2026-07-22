// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package oidcverify

import (
	"context"
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
	JWKSURI       string
	Audience      string
	ClockSkew     time.Duration
	NonceRequired bool
}

type verifier struct {
	cache  *jwk.Cache
	config ProviderConfig
	clock  services.SystemClock
}

func NewVerifier(ctx context.Context, cfg ProviderConfig, clock services.SystemClock) (Verifier, error) {
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
