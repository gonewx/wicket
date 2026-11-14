// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/gonewx/wicket/dp"
)

// PushedAuthorizationRequestURIPrefix starts every request_uri handle the
// server issues for a pushed authorization request. It is the form RFC 9126
// section 2.2 shows, under the OAuth URI sub-namespace RFC 9126 section 7
// registers with IANA.
const PushedAuthorizationRequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// PushedAuthorizationRequestPurpose is the data protection purpose of
// pushed authorization payloads. The protector applied to them is created
// from the pushed authorization data protection seam with this purpose and
// no other.
const PushedAuthorizationRequestPurpose = "wicket.PushedAuthorizationRequest"

// pushedAuthorizationRequestHandleBytes is the entropy of a generated
// request_uri handle.
const pushedAuthorizationRequestHandleBytes = 32

// pushedAuthorizationPayloadVersion is the only payload container version.
const pushedAuthorizationPayloadVersion = 1

// ErrInvalidRequestURI reports a request_uri that is not a pushed
// authorization request handle: it lacks PushedAuthorizationRequestURIPrefix
// or carries nothing after it.
var ErrInvalidRequestURI = errors.New("storage: invalid pushed authorization request_uri")

// PushedAuthorizationRequestKey derives the store key of a pushed
// authorization request from its full request_uri. It is the only way to
// obtain a key: the side that stores a request and the side that resolves a
// presented request_uri both call it, and a store only ever sees the key,
// never the request_uri itself.
//
// The key is the unpadded base64url encoding of the SHA-256 digest of the
// full URN, always 43 characters from [A-Za-z0-9_-]. A request_uri without
// the prefix, or with nothing after it, returns ("", ErrInvalidRequestURI).
func PushedAuthorizationRequestKey(requestURI string) (string, error) {
	if !strings.HasPrefix(requestURI, PushedAuthorizationRequestURIPrefix) || len(requestURI) == len(PushedAuthorizationRequestURIPrefix) {
		return "", ErrInvalidRequestURI
	}
	sum := sha256.Sum256([]byte(requestURI))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// NewPushedAuthorizationRequestURI generates a fresh request_uri handle:
// PushedAuthorizationRequestURIPrefix followed by the unpadded base64url
// encoding of 32 bytes from crypto/rand. A failing random source returns
// ("", err); no partial handle is ever returned.
func NewPushedAuthorizationRequestURI() (string, error) {
	return newPushedAuthorizationRequestURI(rand.Reader)
}

func newPushedAuthorizationRequestURI(entropy io.Reader) (string, error) {
	buf := make([]byte, pushedAuthorizationRequestHandleBytes)
	if _, err := io.ReadFull(entropy, buf); err != nil {
		return "", fmt.Errorf("storage: generate pushed authorization request_uri: %w", err)
	}
	return PushedAuthorizationRequestURIPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// pushedAuthorizationPayload is the versioned container stored as
// PushedAuthorizationRequest.Payload.
type pushedAuthorizationPayload struct {
	Version       int    `json:"version"`
	DataProtected bool   `json:"data_protected"`
	Payload       []byte `json:"payload"`
}

// ProtectPushedAuthorizationParameters encodes the authorization parameters
// of a pushed request and protects them with protector, which must be the
// protector of the pushed authorization data protection seam. The result is
// a versioned container that UnprotectPushedAuthorizationParameters reverses.
//
// The payload carries no binding to its key or record: the purpose is one
// fixed constant, so a payload moved under another record still unprotects
// cleanly. After unprotecting, the core must check the client_id recovered
// from the parameters against the record's ClientId and against the
// requesting client.
func ProtectPushedAuthorizationParameters(protector dp.DataProtector, parameters url.Values) ([]byte, error) {
	if protector == nil {
		return nil, errors.New("storage: protect pushed authorization parameters: no data protector")
	}
	plain, err := json.Marshal(parameters)
	if err != nil {
		return nil, fmt.Errorf("storage: protect pushed authorization parameters: %w", err)
	}
	data, err := json.Marshal(pushedAuthorizationPayload{
		Version:       pushedAuthorizationPayloadVersion,
		DataProtected: true,
		Payload:       protector.Protect(plain),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: protect pushed authorization parameters: %w", err)
	}
	return data, nil
}

// UnprotectPushedAuthorizationParameters reverses
// ProtectPushedAuthorizationParameters. A nil protector, a container that is
// not valid JSON, an unknown version, a container not marked as protected, or
// a payload the protector rejects all return an error and no parameters.
// The payload is not bound to its key or record; see
// ProtectPushedAuthorizationParameters for the client_id check the core
// must perform after unprotecting.
func UnprotectPushedAuthorizationParameters(protector dp.DataProtector, payload []byte) (url.Values, error) {
	if protector == nil {
		return nil, errors.New("storage: unprotect pushed authorization parameters: no data protector")
	}
	var container pushedAuthorizationPayload
	if err := json.Unmarshal(payload, &container); err != nil {
		return nil, fmt.Errorf("storage: unprotect pushed authorization parameters: %w", err)
	}
	if container.Version != pushedAuthorizationPayloadVersion {
		return nil, fmt.Errorf("storage: unprotect pushed authorization parameters: unknown payload version %d", container.Version)
	}
	if !container.DataProtected {
		return nil, errors.New("storage: unprotect pushed authorization parameters: payload not data protected")
	}
	plain, err := protector.Unprotect(container.Payload)
	if err != nil {
		return nil, fmt.Errorf("storage: unprotect pushed authorization parameters: %w", err)
	}
	var parameters url.Values
	if err := json.Unmarshal(plain, &parameters); err != nil {
		return nil, fmt.Errorf("storage: unprotect pushed authorization parameters: %w", err)
	}
	if parameters == nil {
		parameters = url.Values{}
	}
	return parameters, nil
}
