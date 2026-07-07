// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"

	"github.com/gonewx/wicket/models"
)

type JsonWebKeysResult struct {
	WebKeys []*models.JsonWebKey

	MaxAge *int
}

func NewJsonWebKeysResult(
	webKeys []*models.JsonWebKey,
	maxAge *int,
) *JsonWebKeysResult {
	return &JsonWebKeysResult{
		WebKeys: webKeys,
		MaxAge:  maxAge,
	}
}

func (jwkr *JsonWebKeysResult) Execute(w http.ResponseWriter, r *http.Request) error {
	if jwkr.MaxAge != nil && *jwkr.MaxAge >= 0 {
		HttpRespSetCache(w, *jwkr.MaxAge, "Origin")
	}

	resp := make(map[string]interface{})
	resp["keys"] = jwkr.WebKeys

	return HttpRespWriteJson(w, resp, "")
}
