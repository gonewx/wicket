// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package jwt

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
	authevents "github.com/gonewx/wicket/auth/core/events"
)

type ForbiddenContext struct {
	*authevents.ResultContext[*Options]
}

func NewForbiddenContext(
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options *Options,
) *ForbiddenContext {
	return &ForbiddenContext{
		ResultContext: authevents.NewResultContext(r, w, scheme, options),
	}
}
