// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"
)

type IntrospectionResult struct {
	Entries map[string]any
}

func NewIntrospectionResult(
	entries map[string]any,
) *IntrospectionResult {
	return &IntrospectionResult{
		Entries: entries,
	}
}

func (ddr *IntrospectionResult) Execute(w http.ResponseWriter, r *http.Request) error {
	HttpRespSetNoCache(w)

	return HttpRespWriteJson(w, ddr.Entries, "")
}
