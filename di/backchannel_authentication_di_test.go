// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di_test

import (
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/storage"
)

func TestBackchannelAuthenticationServicesResolveFromContainer(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Fatalf("close root: %v", err)
		}
	})

	if root.NewPtr_BackchannelAuthenticationHandler() == nil {
		t.Fatal("BackchannelAuthenticationHandler did not resolve")
	}
	if root.NewBackchannelAuthenticationRequestValidator() == nil {
		t.Fatal("BackchannelAuthenticationRequestValidator did not resolve")
	}
	if root.NewBackchannelAuthenticationRequestIdValidator() == nil {
		t.Fatal("BackchannelAuthenticationRequestIdValidator did not resolve")
	}
	if root.NewResourceValidator() == nil {
		t.Fatal("ResourceValidator did not resolve")
	}
	if godi.GetRequired[storage.BackchannelAuthenticationRequestStore](root) == nil {
		t.Fatal("BackchannelAuthenticationRequestStore did not resolve")
	}
}
