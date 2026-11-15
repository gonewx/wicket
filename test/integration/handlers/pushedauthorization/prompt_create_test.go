// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauthorization

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/gonewx/wicket"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func withAccountCreation(p *integration_common.WicketPipeline) {
	p.Root.ServerConfig().SetAccountCreationUrl("/custom")
}

// TestPushedCreatePromptReachesAccountCreation pushes prompt=create and
// follows the request through the account creation page back to the client.
func TestPushedCreatePromptReachesAccountCreation(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{configure: withAccountCreation})

	values := authorizationParameters(parClient)
	values.Set(wicket.AuthorizeRequestPrompt, wicket.PromptModesCreate)
	r := s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, values, parClient, nil)
	if r.status != http.StatusCreated {
		t.Fatalf("push: status %d body %s", r.status, r.body)
	}

	status, location := s.browse(s.authorizeUrl(parClient, r.field("request_uri")))
	if status != http.StatusFound {
		t.Fatalf("authorize answered %d", status)
	}
	target, err := url.Parse(location)
	if err != nil || target.Path != "/custom" {
		t.Fatalf("redirected to %q, want the account creation page", location)
	}
	assertOnlyHandleParameters(t, returnParameters(t, location))

	if status, _ := s.browse(location); status != http.StatusOK || !s.pipeline.CustomWasCalled {
		t.Fatalf("account creation page answered %d, called %v", status, s.pipeline.CustomWasCalled)
	}
	if s.pipeline.CustomRequest == nil || !slices.Contains(s.pipeline.CustomRequest.PromptModes, wicket.PromptModesCreate) {
		t.Fatalf("account creation context = %+v", s.pipeline.CustomRequest)
	}

	s.login()
	s.pipeline.LoginWasCalled = false
	o := s.authorize(target.Query().Get("returnUrl"))
	if o.code == "" || s.pipeline.LoginWasCalled {
		t.Fatalf("outcome %+v, login page reached %v", o, s.pipeline.LoginWasCalled)
	}
}

// TestPushedCreatePromptRefusedWithoutAccountCreation checks that the
// pushed authorization request endpoint refuses prompt=create while no
// account creation page is configured.
func TestPushedCreatePromptRefusedWithoutAccountCreation(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})

	values := authorizationParameters(parClient)
	values.Set(wicket.AuthorizeRequestPrompt, wicket.PromptModesCreate)
	r := s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, values, parClient, nil)
	if r.status != http.StatusBadRequest || r.field("error") != "invalid_request" {
		t.Fatalf("push: status %d body %s", r.status, r.body)
	}
	if got := r.field("error_description"); got != "prompt value create is not supported" {
		t.Fatalf("error_description = %q", got)
	}
}
