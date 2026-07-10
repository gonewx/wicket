// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"crypto"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/gonewx/wicket/tokens"
)

//go:embed test_signing_key.pem
var signingKeyPEM []byte

func loadCertFile() ([]byte, error) {
	return signingKeyPEM, nil
}

func Load() ([]byte, error) {
	src, err := loadCertFile()
	if err != nil {
		return nil, err
	}

	for {
		block, rest := pem.Decode(src)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return block.Bytes, nil
		}
		src = rest
	}

	return nil, fmt.Errorf("No private key found ")
}

func LoadKey() (jwk.Key, error) {
	src, err := loadCertFile()
	if err != nil {
		return nil, err
	}
	key, err := jwk.ParseKey(src, jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}
	thumbprint, err := key.Thumbprint(crypto.MD5)
	if err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyIDKey, strings.ToUpper(hex.EncodeToString(thumbprint))); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, err
	}

	return key, nil
}

func LoadSigningCredentials() (*tokens.SigningCredentials, error) {
	block, err := Load()
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(block)
	if err != nil {
		return nil, err
	}

	return tokens.NewSigningCredentials(
		key,
		tokens.WithAlgorithm(string(jwa.RS256)),
	)
}
