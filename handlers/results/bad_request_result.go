// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"
)

type BadRequestResult struct {
	Error            error
	ErrorDescription string
}

func NewBadRequestResult(
	err error,
	errorDescription string,
) *BadRequestResult {
	return &BadRequestResult{
		Error:            err,
		ErrorDescription: errorDescription,
	}
}

func (brr *BadRequestResult) Execute(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusBadRequest)
	HttpRespSetNoCache(w)

	if brr.Error != nil {
		dto := make(map[string]interface{})
		dto["error"] = brr.Error.Error()
		dto["error_description"] = brr.ErrorDescription

		return HttpRespWriteJson(w, dto, "")
	}

	return nil
}
