// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package auth

type RemoteHandlerOverride interface {
	// Authenticate the user identity with the identity provider.
	// The method process the request on the endpoint defined by CallbackPath.
	HandleRemoteAuthenticate() (*HandleRequestResult, error)
	CreateEvents() any
}
