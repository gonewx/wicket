// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"testing"

	storage_models "github.com/gonewx/wicket/storage/models"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

func TestClientConfigurationValidatorInitiateLoginUriRule(t *testing.T) {
	t.Parallel()
	const notHttps = "client registers an initiate_login_uri that is not an absolute https URI"
	cases := map[string]struct {
		uri     string
		message string
	}{
		"not registered":        {uri: ""},
		"https":                 {uri: "https://rp.example/login"},
		"https upper case":      {uri: "HTTPS://rp.example/login?tenant=a"},
		"https with port":       {uri: "https://rp.example:8443/login"},
		"http":                  {uri: "http://rp.example/login", message: notHttps},
		"relative path":         {uri: "/login", message: notHttps},
		"empty host":            {uri: "https:///x", message: notHttps},
		"no scheme":             {uri: "rp.example/login", message: notHttps},
		"scheme only":           {uri: "https://", message: notHttps},
		"port without host":     {uri: "https://:443/login", message: notHttps},
		"opaque":                {uri: "https:rp.example", message: notHttps},
		"unparsable escape":     {uri: "https://rp.example/%zz", message: notHttps},
		"other absolute scheme": {uri: "custom://rp.example/login", message: notHttps},
		"unparsable query":      {uri: "https://rp.example/login?a=%zz", message: notHttps},
		"semicolon in query":    {uri: "https://rp.example/login?a=1;b=2", message: notHttps},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := storage_models.NewClient()
			client.ClientId = "client"
			client.InitiateLoginUri = tc.uri
			context := validators_contexts.NewClientConfigurationValidationContext(client)
			NewClientConfigurationValidator(nil).Validate(context)
			if tc.message == "" {
				if !context.IsValid {
					t.Fatalf("invalid: %q", context.ErrorMessage)
				}
				return
			}
			if context.IsValid || context.ErrorMessage != tc.message {
				t.Fatalf("valid=%v message=%q, want %q", context.IsValid, context.ErrorMessage, tc.message)
			}
		})
	}
}

func TestClientConfigurationValidatorKeepsEarlierRuleMessage(t *testing.T) {
	t.Parallel()
	client := storage_models.NewClient()
	client.ClientId = "client"
	client.RequireDPoP = true
	client.InitiateLoginUri = "http://rp.example/login"
	context := validators_contexts.NewClientConfigurationValidationContext(client)
	NewClientConfigurationValidator(nil).Validate(context)
	const want = "client requires DPoP but the feature is not enabled"
	if context.IsValid || context.ErrorMessage != want {
		t.Fatalf("valid=%v message=%q, want %q", context.IsValid, context.ErrorMessage, want)
	}
}
