// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"net/http"
	"testing"
	"time"
)

// spyClock records whether Now was consulted and returns a fixed instant, so a
// test can assert the correlation builder stamps expiry through the injected
// clock rather than the wall clock.
type spyClock struct {
	now    time.Time
	called bool
}

func (c *spyClock) Now() time.Time {
	c.called = true
	return c.now
}

// TestCorrelationBuilderUsesInjectedClock proves the correlation cookie builder
// takes its build-stamp time from the injected clock through the embedded seam.
// Production-state correlation cookies never set an Expiration, so the observable
// signal is that the injected clock's Now is consulted at all; a second case sets
// an Expiration to assert the stamped value flows through.
func TestCorrelationBuilderUsesInjectedClock(t *testing.T) {
	t.Parallel()

	fixed := time.Date(2026, 7, 21, 8, 0, 0, 0, time.UTC)

	t.Run("production state consults injected clock", func(t *testing.T) {
		t.Parallel()

		o := NewRemoteOptions()
		builder := o.CorrelationCookie()
		clock := &spyClock{now: fixed}
		builder.SetClock(clock)

		req, _ := http.NewRequest("GET", "http://example.com/", nil)
		opts := builder.Build(req)

		if !clock.called {
			t.Fatal("expected the injected clock to be consulted by Build")
		}
		// AC#4 zero-drift: correlation cookie never sets Expiration, so Expires
		// stays nil regardless of the clock (session cookie).
		if opts.Expires != nil {
			t.Fatalf("expected nil Expires for a correlation cookie, got %v", *opts.Expires)
		}
	})

	t.Run("injected clock stamps expiry when Expiration is set", func(t *testing.T) {
		t.Parallel()

		o := NewRemoteOptions()
		builder := o.CorrelationCookie()
		exp := 30 * time.Minute
		o.correlationCookieBuilder.Expiration = &exp
		builder.SetClock(&spyClock{now: fixed})

		req, _ := http.NewRequest("GET", "http://example.com/", nil)
		opts := builder.Build(req)

		if opts.Expires == nil {
			t.Fatal("expected non-nil Expires when Expiration is set")
		}
		want := fixed.Add(exp)
		if !opts.Expires.Equal(want) {
			t.Fatalf("expected expires %v from injected clock, got %v", want, *opts.Expires)
		}
	})
}
