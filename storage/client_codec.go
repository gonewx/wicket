// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gonewx/wicket/storage/models"
)

// clientCodecVersion is the envelope version EncodeClient writes and the only
// one DecodeClient reads.
const clientCodecVersion = 1

// clientEnvelope is the versioned form of an encoded client. The allowed grant
// types travel in their own field because the client keeps them behind
// accessors that validate the combination.
type clientEnvelope struct {
	Version           int             `json:"version"`
	Client            json.RawMessage `json:"client"`
	AllowedGrantTypes []string        `json:"allowed_grant_types"`
}

// EncodeClient serializes a client into the opaque bytes a client
// registration adapter stores. The bytes are a versioned envelope; an adapter
// stores them as they are and restores the client with DecodeClient. The codec
// encodes Secret.Value as given and does not hash or protect it: callers must
// store secret hashes in the client, never plain secrets.
func EncodeClient(client *models.Client) ([]byte, error) {
	if client == nil {
		return nil, errors.New("storage: encode client: nil client")
	}
	body, err := json.Marshal(client)
	if err != nil {
		return nil, fmt.Errorf("storage: encode client: %w", err)
	}
	data, err := json.Marshal(clientEnvelope{
		Version:           clientCodecVersion,
		Client:            body,
		AllowedGrantTypes: client.AllowedGrantTypes(),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: encode client: %w", err)
	}
	return data, nil
}

// DecodeClient restores a client from bytes written by EncodeClient. It
// returns an error, and no client, for an unknown envelope version, for
// malformed input and for allowed grant types that fail validation.
func DecodeClient(data []byte) (*models.Client, error) {
	var envelope clientEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("storage: decode client: %w", err)
	}
	if envelope.Version != clientCodecVersion {
		return nil, fmt.Errorf("storage: decode client: unsupported envelope version %d", envelope.Version)
	}
	if len(envelope.Client) == 0 || bytes.Equal(envelope.Client, []byte("null")) {
		return nil, errors.New("storage: decode client: envelope carries no client")
	}
	// Decode onto the constructor defaults, so a field the stored body lacks
	// (one added after the record was written) keeps its default rather than
	// the zero value.
	client := models.NewClient()
	if err := json.Unmarshal(envelope.Client, client); err != nil {
		return nil, fmt.Errorf("storage: decode client: %w", err)
	}
	if envelope.AllowedGrantTypes != nil {
		if err := client.SetAllowedGrantTypes(envelope.AllowedGrantTypes); err != nil {
			return nil, fmt.Errorf("storage: decode client: allowed grant types: %w", err)
		}
	}
	return client, nil
}
