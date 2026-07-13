// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

// Base context for authentication events which contain Properties".
type PropertiesContext[T auth.SchemeOptions[T]] struct {
	*BaseContext[T]

	Properties *auth.Properties
}

func NewPropertiesContext[T auth.SchemeOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
	properties *auth.Properties,
) *PropertiesContext[T] {
	if properties == nil {
		properties = auth.NewProperties()
	}
	return &PropertiesContext[T]{
		BaseContext: NewBaseContext(r, w, scheme, options),
		Properties:  properties,
	}
}
