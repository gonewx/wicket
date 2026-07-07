// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type StubAuthorizeResponseGenerator struct {
	Response *responses_models.AuthorizeResponse
}

func NewStubAuthorizeResponseGenerator() *StubAuthorizeResponseGenerator {
	return &StubAuthorizeResponseGenerator{
		Response: responses_models.NewAuthorizeResponse(),
	}
}

func (v *StubAuthorizeResponseGenerator) Create(req *validators_models.ValidatedAuthorizeRequest) (*responses_models.AuthorizeResponse, error) {
	return v.Response, nil
}
