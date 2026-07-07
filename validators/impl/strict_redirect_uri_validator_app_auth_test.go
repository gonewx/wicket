// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"testing"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/stretchr/testify/require"
)

var (
	clientWithValidLoopbackRedirectUri = &storage_models.Client{
		RequirePkce: true,
		RedirectUris: []string{
			"http://127.0.0.1",
		},
	}
)

func TestIsRedirectUriValid(t *testing.T) {
	require := require.New(t)

	tests := []struct {
		uri   string
		valid bool
	}{
		{uri: "http://127.0.0.1", valid: true}, // This is in the clients redirect URIS
		{uri: "http://127.0.0.1:0", valid: true},
		{uri: "http://127.0.0.1:80", valid: true},
		{uri: "http://127.0.0.1:65535", valid: true},
		{uri: "http://127.0.0.1:123/a/b", valid: true},
		{uri: "http://127.0.0.1:123?q=123", valid: true},
		{uri: "http://127.0.0.1:443/?q=123", valid: true},
		{uri: "http://127.0.0.1:443/a/b?q=123", valid: true},
		{uri: "http://127.0.0.1:443#abc", valid: true},
		{uri: "http://127.0.0.1:443/a/b?q=123#abc", valid: true},
		{uri: "", valid: false},
		{uri: "http:", valid: false},
		{uri: "127.0.0.1", valid: false},
		{uri: "//127.0.0.1", valid: false},
		{uri: "https://127.0.0.1:123", valid: false},
		{uri: "http://127.0.0.1:", valid: false},
		{uri: "http://127.0.0.1:-1", valid: false},
		{uri: "http://127.0.0.2:65536", valid: false},
		{uri: "http://127.0.0.1:443a", valid: false},
		{uri: "http://127.0.0.1:a443", valid: false},
		{uri: "http://127.0.0.1:443a/", valid: false},
		{uri: "http://127.0.0.1:443a?", valid: false},
		{uri: "http://127.0.0.2:443", valid: false},
		{uri: "http://127.0.0.1#abc", valid: false},
		{uri: "http://127.0.0.1:#abc", valid: false},
	}

	v := &StrictRedirectUriValidatorAppAuth{}
	for _, test := range tests {
		t.Run(test.uri, func(t *testing.T) {
			require.Equal(test.valid, v.IsRedirectUriValid(test.uri, clientWithValidLoopbackRedirectUri))
		})
	}
}
