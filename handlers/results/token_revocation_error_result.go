// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"
)

type TokenRevocationErrorResult struct {
	Error error
}

func NewTokenRevocationErrorResult(
	err error,
) *TokenRevocationErrorResult {
	return &TokenRevocationErrorResult{
		Error: err,
	}
}

func (brr *TokenRevocationErrorResult) Execute(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusBadRequest)

	dto := make(map[string]interface{})
	dto["error"] = brr.Error.Error()

	return HttpRespWriteJson(w, dto, "")
}
