// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"
)

type StatusCodeResult struct {
	StatusCode int
}

func NewStatusCodeResult(
	statusCode int,
) *StatusCodeResult {
	return &StatusCodeResult{
		StatusCode: statusCode,
	}
}

func (scr *StatusCodeResult) Execute(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(scr.StatusCode)

	return nil
}
