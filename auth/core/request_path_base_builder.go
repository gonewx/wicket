// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"net/http"
	"time"

	gois "github.com/gonewx/wicket"
	cookiespkg "github.com/gonewx/wicket/cookies"
)

type RequestPathBaseBuilder struct {
	*cookiespkg.BaseBuilder

	AdditionalPath string
}

func NewRequestPathBaseBuilder(opts ...gois.Option[RequestPathBaseBuilder]) *RequestPathBaseBuilder {
	b := &RequestPathBaseBuilder{}
	b.BaseBuilder = cookiespkg.NewBaseBuilder()

	for _, opt := range opts {
		opt(b)
	}

	return b
}

func NewBuilderByRequestPathBaseBuilder(opts ...gois.Option[RequestPathBaseBuilder]) *RequestPathBaseBuilder {
	b := NewRequestPathBaseBuilder(opts...)

	return b
}

func (b *RequestPathBaseBuilder) BuildWithExpires(req *http.Request, expiresFrom time.Time) *cookiespkg.Options {
	// check if the user has overridden the default value of path. If so, use that instead of our default value.
	path := b.Path()
	if path == "" {
		feature := FeatureFrom(req.Context())
		if feature != nil {
			originalPathBase := feature.OriginalPathBase()
			// TODO: support pathbase
			// if originalPathBase == "" {
			// 	originalPathBase = req.URL.PathBase
			// }
			path = originalPathBase + b.AdditionalPath
		}
	}
	options := b.BaseBuilder.BuildWithExpires(req, expiresFrom)

	if path != "" {
		options.Path = path
	} else {
		options.Path = "/"
	}

	return options
}
