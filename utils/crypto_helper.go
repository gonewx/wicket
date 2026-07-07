// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package utils

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

type OutputFormat int

const (
	// URL-safe Base64
	Base64Url OutputFormat = iota
	// Base64
	Base64
	// Hex
	Hex
)

func CreateHashClaimValue(value string, tokenSigningAlgorithm string) (string, error) {
	sha, err := GetHashAlgorithmForSigningAlgorithm(tokenSigningAlgorithm)
	if err != nil {
		return "", err
	}

	d := sha.New()
	d.Write([]byte(value))

	hash := d.Sum(nil)

	size := d.Size() / 2

	leftPart := make([]byte, size)
	copy(leftPart, hash[:size])
	return base64.RawURLEncoding.EncodeToString(leftPart), nil
}

func GetHashAlgorithmForSigningAlgorithm(signingAlgorithm string) (crypto.Hash, error) {
	signingAlgorithmBits, err := strconv.ParseInt(signingAlgorithm[len(signingAlgorithm)-3:], 10, 64)
	if err != nil {
		return 0, err
	}

	switch signingAlgorithmBits {
	case 256:
		return crypto.SHA256, nil
	case 384:
		return crypto.SHA384, nil
	case 512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("Invalid signing algorithm: %s", signingAlgorithm)
	}
}

func GetCurveFromSigningAlgorithm(alg string) elliptic.Curve {
	switch alg {
	case "ES256":
		return elliptic.P256()
	case "ES384":
		return elliptic.P384()
	case "ES512":
		return elliptic.P521()
	default:
		return nil
	}
}

func CreateRandomKey(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func CreateUniqueId(length int, format OutputFormat) (string, error) {
	b, err := CreateRandomKey(length)
	if err != nil {
		return "", err
	}

	id := ""
	switch format {
	case Base64Url:
		id = base64.URLEncoding.EncodeToString(b)
	case Base64:
		id = base64.StdEncoding.EncodeToString(b)
	case Hex:
		id = strings.Replace(hex.EncodeToString(b), "-", "", -1)
	default:
		return "", fmt.Errorf("Invalid output format")
	}

	return strings.ToUpper(id), nil
}
