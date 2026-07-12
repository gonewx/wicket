// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/tokens"
	"github.com/gonewx/wicket/utils"
)

type TestCert struct {
}

func NewTestCert() *TestCert {
	return &TestCert{}
}

var (
	generatedKeyPemOnce sync.Once
	generatedKeyPem     []byte
	generatedKeyPemErr  error
)

// loadCertFile prefers an on-disk key file next to the test binary and falls
// back to one process-wide generated RSA key, so packages without the fixture
// file can still build their key-based client secrets.
func loadCertFile() ([]byte, error) {
	certFile := path.Join(utils.AppBasePath(), "gois.example.com-key.pem")
	if src, err := os.ReadFile(certFile); err == nil {
		return src, nil
	}

	generatedKeyPemOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			generatedKeyPemErr = err
			return
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			generatedKeyPemErr = err
			return
		}
		generatedKeyPem = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	})

	return generatedKeyPem, generatedKeyPemErr
}

func (c *TestCert) Load() ([]byte, error) {
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

func (c *TestCert) LoadKey() (jwk.Key, error) {
	src, err := loadCertFile()
	if err != nil {
		return nil, err
	}
	key, err := jwk.ParseKey(src, jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}

	if err := jwk.AssignKeyID(key); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, err
	}

	return key, nil
}

func (c *TestCert) LoadSigningCredentials() (*tokens.SigningCredentials, error) {
	key, err := c.LoadKey()
	if err != nil {
		return nil, err
	}

	var securityKey any
	err = key.Raw(&securityKey)
	if err != nil {
		return nil, err
	}

	return tokens.NewSigningCredentials(securityKey, tokens.WithAlgorithm(string(jwa.RS256)))
}

func (c *TestCert) LoadSigningCredentialsFromRaw(raw string, alg jwa.SignatureAlgorithm) (*tokens.SigningCredentials, error) {
	key, err := jwk.ParseKey([]byte(raw))
	if err != nil {
		return nil, err
	}

	var securityKey any
	err = key.Raw(&securityKey)
	if err != nil {
		return nil, err
	}

	opts := []gois.Option[tokens.SigningCredentials]{tokens.WithAlgorithm(string(alg))}
	if key.KeyID() != "" {
		opts = append(opts, tokens.WithKid(key.KeyID()))
	}

	return tokens.NewSigningCredentials(securityKey, opts...)
}

func (c *TestCert) CreateRsaSecurityKey() (tokens.SecurityKey, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return rsaKey, nil
}

// From: IdentityServer4/test/IdentityServer.UnitTests/Common/TestCert.cs
// LoadCertficateAndKeyFromFile reads file, divides into key and certificates
func LoadCertficateAndKeyFromFile(path string) (*tls.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cert tls.Certificate
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else {
			cert.PrivateKey, err = parsePrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("Failure reading private key from \"%s\": %s", path, err)
			}
		}
		raw = rest
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("No certificate found in \"%s\"", path)
	} else if cert.PrivateKey == nil {
		return nil, fmt.Errorf("No private key found in \"%s\"", path)
	}

	return &cert, nil
}

// LoadCertificateDirectory globs all .pem files in given directory, parses them
// for certs (and private keys) and returns them
func LoadCertificateDirectory(dir string) ([]*tls.Certificate, error) {
	// read certificate files
	certficateFiles, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, fmt.Errorf("Failed to scan certificate dir \"%s\": %s", dir, err)
	}
	sort.Strings(certficateFiles)
	certs := make([]*tls.Certificate, 0)
	for _, file := range certficateFiles {
		cert, err := LoadCertficateAndKeyFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("common(tls): %s", err)
		} else {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("Failed to parse private key")
}
