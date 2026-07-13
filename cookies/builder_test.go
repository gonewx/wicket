// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package cookies

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestNewBaseBuilderDefaults(t *testing.T) {
	t.Parallel()

	b := NewBaseBuilder()

	if b.Name() != "" {
		t.Fatalf("expected empty name, got %q", b.Name())
	}
	if b.Path() != "" {
		t.Fatalf("expected empty path, got %q", b.Path())
	}
	if b.SameSite() != http.SameSiteDefaultMode {
		t.Fatalf("expected SameSiteDefaultMode, got %d", b.SameSite())
	}
	if b.SecurePolicy() != CookieSecurePolicySameAsRequest {
		t.Fatalf("expected SameAsRequest policy, got %d", b.SecurePolicy())
	}
	if b.IsEssential() {
		t.Fatal("expected IsEssential false by default")
	}
}

func TestBaseBuilderSetters(t *testing.T) {
	t.Parallel()

	b := NewBaseBuilder()
	b.SetName("session")
	b.SetPath("/app")
	b.SetSameSite(http.SameSiteStrictMode)
	b.SetSecurePolicy(CookieSecurePolicyAlways)
	b.SetIsEssential(true)

	if b.Name() != "session" {
		t.Fatalf("expected name %q, got %q", "session", b.Name())
	}
	if b.Path() != "/app" {
		t.Fatalf("expected path %q, got %q", "/app", b.Path())
	}
	if b.SameSite() != http.SameSiteStrictMode {
		t.Fatalf("expected SameSiteStrictMode, got %d", b.SameSite())
	}
	if b.SecurePolicy() != CookieSecurePolicyAlways {
		t.Fatalf("expected CookieSecurePolicyAlways, got %d", b.SecurePolicy())
	}
	if !b.IsEssential() {
		t.Fatal("expected IsEssential true")
	}
}

func TestBuildWithExpires(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure func(*BaseBuilder)
		tlsConn   bool
		wantPath  string
		wantSec   bool
	}{
		"default path is slash": {
			configure: func(b *BaseBuilder) {},
			wantPath:  "/",
			wantSec:   false,
		},
		"custom path preserved": {
			configure: func(b *BaseBuilder) {
				b.SetPath("/custom")
			},
			wantPath: "/custom",
			wantSec:  false,
		},
		"always secure ignores TLS state": {
			configure: func(b *BaseBuilder) {
				b.SetSecurePolicy(CookieSecurePolicyAlways)
			},
			tlsConn:  false,
			wantPath: "/",
			wantSec:  true,
		},
		"same as request with TLS": {
			configure: func(b *BaseBuilder) {
				b.SetSecurePolicy(CookieSecurePolicySameAsRequest)
			},
			tlsConn:  true,
			wantPath: "/",
			wantSec:  true,
		},
		"same as request without TLS": {
			configure: func(b *BaseBuilder) {
				b.SetSecurePolicy(CookieSecurePolicySameAsRequest)
			},
			tlsConn:  false,
			wantPath: "/",
			wantSec:  false,
		},
		"none policy always insecure": {
			configure: func(b *BaseBuilder) {
				b.SetSecurePolicy(CookieSecurePolicyNone)
			},
			tlsConn:  true,
			wantPath: "/",
			wantSec:  false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			b := NewBaseBuilder()
			tc.configure(b)

			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			if tc.tlsConn {
				req.TLS = &tls.ConnectionState{}
			}

			opts := b.BuildWithExpires(req, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

			if opts.Path != tc.wantPath {
				t.Fatalf("expected path %q, got %q", tc.wantPath, opts.Path)
			}
			if opts.Secure != tc.wantSec {
				t.Fatalf("expected Secure=%v, got %v", tc.wantSec, opts.Secure)
			}
		})
	}
}

func TestBuildExpirationComputation(t *testing.T) {
	t.Parallel()

	b := NewBaseBuilder()
	exp := 30 * time.Minute
	b.Expiration = &exp

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	base := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	opts := b.BuildWithExpires(req, base)

	if opts.Expires == nil {
		t.Fatal("expected non-nil Expires")
	}
	want := base.Add(30 * time.Minute)
	if !opts.Expires.Equal(want) {
		t.Fatalf("expected expires %v, got %v", want, *opts.Expires)
	}
}

func TestBuildNoExpirationReturnsNil(t *testing.T) {
	t.Parallel()

	b := NewBaseBuilder()
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	opts := b.BuildWithExpires(req, time.Now())

	if opts.Expires != nil {
		t.Fatalf("expected nil Expires when no Expiration set, got %v", *opts.Expires)
	}
}

func TestBuildPassesThroughFields(t *testing.T) {
	t.Parallel()

	b := NewBaseBuilder()
	b.Domain = "example.com"
	b.HttpOnly = true
	b.SetSameSite(http.SameSiteLaxMode)
	b.SetIsEssential(true)
	maxAge := 3600 * time.Second
	b.MaxAge = &maxAge

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	opts := b.Build(req)

	if opts.Domain != "example.com" {
		t.Fatalf("expected domain %q, got %q", "example.com", opts.Domain)
	}
	if !opts.HttpOnly {
		t.Fatal("expected HttpOnly true")
	}
	if opts.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSiteLaxMode, got %d", opts.SameSite)
	}
	if !opts.IsEssential {
		t.Fatal("expected IsEssential true")
	}
	if opts.MaxAge == nil || *opts.MaxAge != maxAge {
		t.Fatalf("expected MaxAge %v, got %v", maxAge, opts.MaxAge)
	}
}
