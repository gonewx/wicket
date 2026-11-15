// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage/models"
)

// TestRefreshTokenStoreCopiesTheConsumedTime pins that the in-memory store
// keeps its own consumed time: neither the value written nor the value read
// shares it with the caller, so a caller cannot unmark a consumed token.
func TestRefreshTokenStoreCopiesTheConsumedTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	consumedAt := time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)
	want := consumedAt
	token := models.NewRefreshToken()
	token.ConsumedTime = &consumedAt
	token.RotatedTo = "successor"

	store := NewRefreshTokenStore()
	if err := store.StoreRefreshToken(ctx, "handle", token); err != nil {
		t.Fatal(err)
	}
	consumedAt = consumedAt.Add(time.Hour)

	read, err := store.GetRefreshToken(ctx, "handle")
	if err != nil {
		t.Fatal(err)
	}
	if read.ConsumedTime == nil || !read.ConsumedTime.Equal(want) || read.RotatedTo != "successor" {
		t.Fatalf("stored consumption %v / %q, want %v / successor", read.ConsumedTime, read.RotatedTo, want)
	}
	*read.ConsumedTime = want.Add(time.Hour)

	again, err := store.GetRefreshToken(ctx, "handle")
	if err != nil {
		t.Fatal(err)
	}
	if !again.ConsumedTime.Equal(want) {
		t.Fatalf("consumed time changed through a read copy: %v, want %v", again.ConsumedTime, want)
	}
}
