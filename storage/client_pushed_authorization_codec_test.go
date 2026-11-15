// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"testing"

	"github.com/gonewx/wicket/storage/models"
)

func TestClientCodecKeepsPushedAuthorizationMetadata(t *testing.T) {
	t.Parallel()
	client := models.NewClient()
	client.ClientId = "pushing"
	client.RequirePushedAuthorizationRequests = true
	client.RequestUriLifetime = 30

	data, err := EncodeClient(client)
	if err != nil {
		t.Fatalf("EncodeClient: %v", err)
	}
	decoded, err := DecodeClient(data)
	if err != nil {
		t.Fatalf("DecodeClient: %v", err)
	}
	if decoded.ClientPushedAuthorizationMetadata != client.ClientPushedAuthorizationMetadata {
		t.Fatalf("decoded metadata = %+v, want %+v", decoded.ClientPushedAuthorizationMetadata, client.ClientPushedAuthorizationMetadata)
	}
}
