// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"
)

type DiscoveryDocumentResult struct {
	Entries map[string]any
	MaxAge  *int
}

func NewDiscoveryDocumentResult(
	entries map[string]any,
	maxAge *int,
) *DiscoveryDocumentResult {
	return &DiscoveryDocumentResult{
		Entries: entries,
		MaxAge:  maxAge,
	}
}

func (ddr *DiscoveryDocumentResult) Execute(w http.ResponseWriter, r *http.Request) error {
	if ddr.MaxAge != nil && *ddr.MaxAge >= 0 {
		HttpRespSetCache(w, *ddr.MaxAge, "Origin")
	}

	return HttpRespWriteJson(w, ddr.Entries, "")
}
