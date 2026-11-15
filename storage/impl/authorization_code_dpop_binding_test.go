// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"testing"

	"github.com/gonewx/wicket/storage/models"
)

// TestAuthorizationCodeKeepsItsDPoPKeyThumbprint pins that the thumbprint an
// authorization code is bound to survives serialization and the in-memory
// copy; losing it would unbind the code.
func TestAuthorizationCodeKeepsItsDPoPKeyThumbprint(t *testing.T) {
	t.Parallel()
	const thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	code := &models.AuthorizationCode{CreationTime: writeSemanticsNow, Lifetime: 300, ClientId: "client"}
	code.DPoPKeyThumbprint = thumbprint

	serializer := NewPersistentGrantSerializer()
	data, err := serializer.Serialize(code)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := serializer.Deserialize[models.AuthorizationCode](data)
	if err != nil {
		t.Fatal(err)
	}
	if restored.DPoPKeyThumbprint != thumbprint {
		t.Fatalf("serialized thumbprint %q, want %q", restored.DPoPKeyThumbprint, thumbprint)
	}

	if copied := copyAuthorizationCode(code); copied.DPoPKeyThumbprint != thumbprint {
		t.Fatalf("copied thumbprint %q, want %q", copied.DPoPKeyThumbprint, thumbprint)
	}
}
