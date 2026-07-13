// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import "github.com/gonewx/wicket/auth"

// Feature Used to capture path info so redirects can be computed properly
type Feature struct {
	originalPathBase string
	originalPath     string
}

func NewFeature() auth.Feature {
	return &Feature{}
}

// The original path base.
func (f *Feature) OriginalPathBase() string {
	return f.originalPathBase
}

func (f *Feature) SetOriginalPathBase(value string) {
	f.originalPathBase = value
}

// The original path.
func (f *Feature) OriginalPath() string {
	return f.originalPath
}

func (f *Feature) SetOriginalPath(value string) {
	f.originalPath = value
}
