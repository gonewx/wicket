// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package jwt

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
	authevents "github.com/gonewx/wicket/auth/core/events"
)

type FailedContext struct {
	*authevents.ResultContext[*Options]

	Error error
}

func NewFailedContext(
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options *Options,
) *FailedContext {
	return &FailedContext{
		ResultContext: authevents.NewResultContext(r, w, scheme, options),
	}
}
