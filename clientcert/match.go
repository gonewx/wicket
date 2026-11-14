// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"slices"
	"strings"
	"time"

	storage_models "github.com/gonewx/wicket/storage/models"
)

// chainTrusted verifies the leaf against the trusted authorities, with the
// other presented certificates as intermediates, for client authentication
// at the given time.
func chainTrusted(certificates []*x509.Certificate, roots *x509.CertPool, now time.Time) bool {
	if roots == nil || len(certificates) == 0 || certificates[0] == nil {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		if certificate != nil {
			intermediates.AddCert(certificate)
		}
	}
	_, err := certificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

// subjectMatches compares the leaf against the single subject attribute the
// client registered. A client registering none or more than one never
// matches.
func subjectMatches(client *storage_models.Client, leaf *x509.Certificate) bool {
	registered := 0
	for _, value := range []string{
		client.TlsClientAuthSubjectDn,
		client.TlsClientAuthSanDns,
		client.TlsClientAuthSanUri,
		client.TlsClientAuthSanIp,
		client.TlsClientAuthSanEmail,
	} {
		if value != "" {
			registered++
		}
	}
	if registered != 1 {
		return false
	}
	switch {
	case client.TlsClientAuthSubjectDn != "":
		return leaf.Subject.String() == client.TlsClientAuthSubjectDn
	case client.TlsClientAuthSanDns != "":
		return slices.ContainsFunc(leaf.DNSNames, func(name string) bool {
			return strings.EqualFold(name, client.TlsClientAuthSanDns)
		})
	case client.TlsClientAuthSanUri != "":
		for _, uri := range leaf.URIs {
			if uri != nil && uri.String() == client.TlsClientAuthSanUri {
				return true
			}
		}
		return false
	case client.TlsClientAuthSanIp != "":
		expected := net.ParseIP(client.TlsClientAuthSanIp)
		if expected == nil {
			return false
		}
		return slices.ContainsFunc(leaf.IPAddresses, expected.Equal)
	default:
		return slices.Contains(leaf.EmailAddresses, client.TlsClientAuthSanEmail)
	}
}

// registeredCertificateMatches reports whether the leaf is, byte for byte,
// the first x5c member of a key in the client's inline JWK Set.
func registeredCertificateMatches(jwks string, leaf *x509.Certificate) bool {
	if jwks == "" {
		return false
	}
	var set struct {
		Keys []struct {
			X5c []string `json:"x5c"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &set); err != nil {
		return false
	}
	for _, key := range set.Keys {
		if len(key.X5c) == 0 {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(key.X5c[0])
		if err != nil {
			continue
		}
		if bytes.Equal(der, leaf.Raw) {
			return true
		}
	}
	return false
}
