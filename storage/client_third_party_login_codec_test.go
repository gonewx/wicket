// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"testing"

	"github.com/gonewx/wicket/storage/models"
)

func TestClientCodecKeepsThirdPartyLoginMetadata(t *testing.T) {
	t.Parallel()
	client := models.NewClient()
	client.ClientId = "initiating"
	client.InitiateLoginUri = "https://rp.example/login?tenant=a"

	data, err := EncodeClient(client)
	if err != nil {
		t.Fatalf("EncodeClient: %v", err)
	}
	decoded, err := DecodeClient(data)
	if err != nil {
		t.Fatalf("DecodeClient: %v", err)
	}
	if decoded.ClientThirdPartyLoginMetadata != client.ClientThirdPartyLoginMetadata {
		t.Fatalf("decoded metadata = %+v, want %+v", decoded.ClientThirdPartyLoginMetadata, client.ClientThirdPartyLoginMetadata)
	}
}
