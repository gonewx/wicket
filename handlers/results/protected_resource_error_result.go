// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"fmt"
	"net/http"

	"github.com/gonewx/wicket"
)

type ProtectedResourceErrorResult struct {
	Error            error
	ErrorDescription string
}

func NewProtectedResourceErrorResult(
	err error,
	errorDescription string,
) *ProtectedResourceErrorResult {
	return &ProtectedResourceErrorResult{
		Error:            err,
		ErrorDescription: errorDescription,
	}
}

func (prer *ProtectedResourceErrorResult) Execute(w http.ResponseWriter, r *http.Request) error {

	statusCode := http.StatusUnauthorized

	if code, ok := gois.ProtectedResourceErrorStatusCodes[prer.Error]; ok {
		statusCode = code
	}

	w.WriteHeader(statusCode)
	HttpRespSetNoCache(w)

	if prer.Error == gois.ProtectedResourceErrorsExpiredToken {
		prer.Error = gois.ProtectedResourceErrorsInvalidToken
		prer.ErrorDescription = "The access token expired"
	}

	errorString := fmt.Sprintf("error=\"%s\"", prer.Error.Error())
	if prer.ErrorDescription == "" {
		w.Header()["www-authenticate"] = []string{"Bearer realm=\"IdentityServer\"", errorString}
	} else {
		errorDescriptionString := fmt.Sprintf("error_description=\"%s\"", prer.ErrorDescription)
		w.Header()["www-authenticate"] = []string{"Bearer realm=\"IdentityServer\"", prer.ErrorDescription, errorDescriptionString}
	}

	return nil
}
