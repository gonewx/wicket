// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
)

// ReturnUrlParser Parses a return URL using all registered URL parsers
type ReturnUrlParser struct {
	parsers []services.ReturnUrlParser
}

func NewReturnUrlParser(parsers []services.ReturnUrlParser) *ReturnUrlParser {
	return &ReturnUrlParser{parsers: parsers}
}

// Parses a return URL.
func (p *ReturnUrlParser) Parse(returnUrl string) (*messages.AuthorizationRequest, error) {
	for _, parser := range p.parsers {
		result, err := parser.Parse(returnUrl)
		if err != nil {
			return nil, err
		}

		if result != nil {
			return result, nil
		}
	}

	return nil, nil
}

// Determines whether the return URL is valid.
func (p *ReturnUrlParser) IsValidReturnUrl(returnUrl string) bool {
	for _, parser := range p.parsers {
		if parser.IsValidReturnUrl(returnUrl) {
			return true
		}
	}

	return false
}
