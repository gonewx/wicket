// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"context"
	"crypto/sha256"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// The P-256 public key and its thumbprint below were produced by this test's
// author: a key generated once with crypto/ecdsa, and the expected value
// computed as the SHA-256 of the canonical JSON
// {"crv":"P-256","kty":"EC","x":"...","y":"..."}, base64url without padding.
const (
	vectorX          = "Ep48UHbIUCLX1z-k50wjZybBvi4EoY_UXW0gEcFlhhY"
	vectorY          = "_eH9VX4KRcAWDrZaWNQOEo1c9xe9M3-zbaZsigNiX3I"
	vectorThumbprint = "uGatKnvG5nkoHsHtX2yGCl3_52iN1zcUmbaBuuekuVo"
)

func TestThumbprintKnownVector(t *testing.T) {
	t.Parallel()
	canonical := `{"crv":"P-256","kty":"EC","x":"` + vectorX + `","y":"` + vectorY + `"}`
	digest := sha256.Sum256([]byte(canonical))
	if b64(digest[:]) != vectorThumbprint {
		t.Fatal("the hard-coded vector does not match its canonical JSON")
	}
	// Members outside the required set and their order do not change it.
	key, err := jwk.ParseKey([]byte(`{"y":"` + vectorY + `","use":"sig","x":"` + vectorX + `","kid":"k1","kty":"EC","crv":"P-256"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Thumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	if got != vectorThumbprint {
		t.Fatalf("Thumbprint = %q, want %q", got, vectorThumbprint)
	}
	if _, err := Thumbprint(nil); err == nil {
		t.Fatal("a nil key has a thumbprint")
	}
}

func TestConfirmation(t *testing.T) {
	t.Parallel()
	if got := Confirmation(vectorThumbprint); got != `{"jkt":"`+vectorThumbprint+`"}` {
		t.Fatalf("Confirmation = %s", got)
	}
}

func TestProofContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if ProofThumbprint(ctx) != "" {
		t.Fatal("a bare context carries a thumbprint")
	}
	if WithProof(ctx, "") != ctx {
		t.Fatal("an empty thumbprint changed the context")
	}
	bound := WithProof(ctx, "tp")
	if ProofThumbprint(bound) != "tp" {
		t.Fatalf("thumbprint %q", ProofThumbprint(bound))
	}
	// Another package's string value under a look-alike key is not read.
	type proofContextKey struct{}
	if ProofThumbprint(context.WithValue(ctx, proofContextKey{}, "x")) != "" {
		t.Fatal("a foreign key was read")
	}
}

func TestAccessTokenBinder(t *testing.T) {
	t.Parallel()
	binder := NewAccessTokenBinder()
	request, _ := http.NewRequest(http.MethodPost, testEndpoint, nil)
	unbound, err := binder.Confirmation(context.Background(), request, "client")
	if err != nil || unbound != "" {
		t.Fatalf("unbound = %q, %v", unbound, err)
	}
	bound, err := binder.Confirmation(WithProof(context.Background(), vectorThumbprint), request, "client")
	if err != nil || bound != Confirmation(vectorThumbprint) {
		t.Fatalf("bound = %q, %v", bound, err)
	}
}
