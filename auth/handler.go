// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package auth

type HandlerOverride interface {
	InitializeHandler() error
	HandleAuthenticate() (*Result, error)
	HandleChallenge(properties *Properties) error
	HandleForbidden(properties *Properties) error
	CreateEvents() any
}
