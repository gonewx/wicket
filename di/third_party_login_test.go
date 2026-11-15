// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"strings"
	"testing"

	storage_models "github.com/gonewx/wicket/storage/models"
)

func clientWithInitiateLoginUri(id, uri string) *storage_models.Client {
	client := &storage_models.Client{ClientId: id}
	client.InitiateLoginUri = uri
	return client
}

func TestFreezeRejectsStaticClientWithNonHttpsInitiateLoginUri(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		uri         string
		useProvider bool
	}{
		"http":                  {uri: "http://rp.example/login"},
		"relative":              {uri: "/login"},
		"no host":               {uri: "https:///login"},
		"scheme only":           {uri: "https://"},
		"no scheme":             {uri: "rp.example/login"},
		"unparsable":            {uri: "https://rp.example/%zz"},
		"http through provider": {uri: "http://rp.example/login", useProvider: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			cfg.AllowInMemoryFallback()
			clients := []*storage_models.Client{
				clientWithInitiateLoginUri("good-client", "https://rp.example/login"),
				clientWithInitiateLoginUri("bad-client", tc.uri),
			}
			if tc.useProvider {
				cfg.SetClientsProvider(func() []*storage_models.Client { return clients })
			} else {
				cfg.SetClients(clients)
			}
			text := panicText(t, cfg.Freeze)
			for _, want := range []string{`"bad-client"`, "initiate_login_uri", "https"} {
				if !strings.Contains(text, want) {
					t.Fatalf("panic %q does not mention %q", text, want)
				}
			}
			if strings.Contains(text, "good-client") {
				t.Fatalf("panic %q names the valid client", text)
			}
		})
	}
}

func TestFreezeAcceptsStaticClientInitiateLoginUris(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure func(*ServerConfig)
	}{
		"no client list": {configure: func(*ServerConfig) {}},
		"empty and https values": {configure: func(c *ServerConfig) {
			c.SetClients([]*storage_models.Client{
				clientWithInitiateLoginUri("unregistered", ""),
				clientWithInitiateLoginUri("registered", "https://rp.example/login?tenant=a"),
				clientWithInitiateLoginUri("upper-scheme", "HTTPS://rp.example/login"),
			})
		}},
		"injected store with no static list": {configure: func(c *ServerConfig) {
			c.SetClientStore(newHostClientStore())
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			cfg.AllowInMemoryFallback()
			tc.configure(cfg)
			cfg.Freeze()
		})
	}
}
