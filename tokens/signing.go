// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package tokens

import "github.com/gonewx/wicket"

type SecurityKey = any

type SecurityToken = any

type SigningCredentials struct {
	Key       SecurityKey
	Algorithm string
	Kid       string
}

func NewSigningCredentials(key SecurityKey, opts ...wicket.Option[SigningCredentials]) (*SigningCredentials, error) {
	credential := &SigningCredentials{Key: key}
	for _, opt := range opts {
		opt(credential)
	}
	return credential, nil
}

func WithAlgorithm(value string) wicket.Option[SigningCredentials] {
	return func(c *SigningCredentials) {
		c.Algorithm = value
	}
}

func WithKid(value string) wicket.Option[SigningCredentials] {
	return func(c *SigningCredentials) {
		c.Kid = value
	}
}
