// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package auth

// Feature Used to capture path info so redirects can be computed properly
type Feature interface {
	// The original path base.
	OriginalPathBase() string
	SetOriginalPathBase(value string)

	// The original path.
	OriginalPath() string
	SetOriginalPath(value string)
}
