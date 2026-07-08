// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// JWA signing algorithm identifiers this manager can generate and select. Values
// are the standard RFC 7518 identifiers.
const (
	AlgRS256 = "RS256"
	AlgRS384 = "RS384"
	AlgRS512 = "RS512"
	AlgES256 = "ES256"
	AlgES384 = "ES384"
	AlgES512 = "ES512"
)

const rsaKeyBits = 2048

// algorithmProfile describes how to generate, recognise and serialize keys for a
// single JWA algorithm.
type algorithmProfile struct {
	generate func(entropy Entropy) (crypto.Signer, error)
	// matchesPrivate reports whether a recovered private key is compatible with
	// this algorithm.
	matchesPrivate func(key crypto.PrivateKey) bool
}

var algorithmProfiles = map[string]algorithmProfile{
	AlgRS256: rsaProfile(),
	AlgRS384: rsaProfile(),
	AlgRS512: rsaProfile(),
	AlgES256: ecProfile(elliptic.P256()),
	AlgES384: ecProfile(elliptic.P384()),
	AlgES512: ecProfile(elliptic.P521()),
}

func rsaProfile() algorithmProfile {
	return algorithmProfile{
		generate: func(entropy Entropy) (crypto.Signer, error) {
			return rsa.GenerateKey(entropy, rsaKeyBits)
		},
		matchesPrivate: func(key crypto.PrivateKey) bool {
			_, ok := key.(*rsa.PrivateKey)
			return ok
		},
	}
}

func ecProfile(curve elliptic.Curve) algorithmProfile {
	return algorithmProfile{
		generate: func(entropy Entropy) (crypto.Signer, error) {
			return ecdsa.GenerateKey(curve, entropy)
		},
		matchesPrivate: func(key crypto.PrivateKey) bool {
			ec, ok := key.(*ecdsa.PrivateKey)
			return ok && ec.Curve == curve
		},
	}
}

// isSupportedAlgorithm reports whether the manager can generate the algorithm.
func isSupportedAlgorithm(alg string) bool {
	_, ok := algorithmProfiles[alg]
	return ok
}

// generatedKey holds a freshly created key pair with its derived public id.
type generatedKey struct {
	signer     crypto.Signer
	publicDER  []byte
	privateDER []byte
	publicID   string
}

// generateKey creates a key pair for the algorithm using the injected entropy,
// then serializes both halves and derives a stable public id.
func generateKey(alg string, entropy Entropy) (*generatedKey, error) {
	profile, ok := algorithmProfiles[alg]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrConfiguration, alg)
	}
	signer, err := profile.generate(entropy)
	if err != nil {
		return nil, fmt.Errorf("generate %s key: %w", alg, err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	publicID, err := derivePublicID(signer.Public())
	if err != nil {
		return nil, err
	}
	return &generatedKey{signer: signer, publicDER: publicDER, privateDER: privateDER, publicID: publicID}, nil
}

// derivePublicID computes a stable JWKS kid from public key material using the
// RFC 7638 JWK thumbprint, so the same public key always yields the same kid.
func derivePublicID(pub crypto.PublicKey) (string, error) {
	key, err := jwk.FromRaw(pub)
	if err != nil {
		return "", fmt.Errorf("derive key id: %w", err)
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("derive key id: %w", err)
	}
	return base64URL(thumb), nil
}

// recoverPrivateKey parses protected-then-unprotected private material and
// verifies it is compatible with the record's algorithm.
func recoverPrivateKey(alg string, privateDER []byte) (crypto.Signer, error) {
	profile, ok := algorithmProfiles[alg]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrConfiguration, alg)
	}
	key, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if !profile.matchesPrivate(key) {
		return nil, fmt.Errorf("%w: key type does not match %q", ErrConfiguration, alg)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: recovered key is not a signer", ErrConfiguration)
	}
	return signer, nil
}

// recoverPublicKey parses PKIX public material into a public key object suitable
// for JWK serialization.
func recoverPublicKey(publicDER []byte) (crypto.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pub, nil
}
