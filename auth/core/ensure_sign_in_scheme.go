// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"fmt"

	"github.com/gonewx/wicket/auth"
	optspkg "github.com/gonewx/wicket/di/options"
)

var _ optspkg.PostConfigureOptions[*RemoteOptions] = (*EnsureSignInScheme[*RemoteOptions])(nil)

type EnsureSignInScheme[T auth.RemoteOptions[T]] struct {
	authOptions func() optspkg.Options[*auth.Options]
}

func NewEnsureSignInScheme[T auth.RemoteOptions[T]](authOptions optspkg.Options[*auth.Options]) *EnsureSignInScheme[T] {
	return &EnsureSignInScheme[T]{
		authOptions: func() optspkg.Options[*auth.Options] {
			return authOptions
		},
	}
}

func (e *EnsureSignInScheme[T]) PostConfigure(name string, options T) error {
	if options.SignInScheme() != "" {
		return nil
	}

	authOptions := e.authOptions()
	if authOptions == nil {
		return fmt.Errorf("EnsureSignInScheme: auth options are not initialized")
	}

	o, err := authOptions.Value()
	if err != nil {
		return fmt.Errorf("EnsureSignInScheme: resolve auth options: %w", err)
	}
	if o == nil {
		return nil
	}

	if o.DefaultSignInScheme != "" {
		options.SetSignInScheme(o.DefaultSignInScheme)
		return nil
	}

	options.SetSignInScheme(o.DefaultScheme)

	return nil
}
