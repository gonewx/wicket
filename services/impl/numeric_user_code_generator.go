// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"math/rand"
	"strconv"

	"github.com/gonewx/wicket"
)

// NumericUserCodeGenerator Implements device flow user code generation
type NumericUserCodeGenerator struct {
	UserCodeType string
	RetryLimit   int
}

func NewNumericUserCodeGenerator() *NumericUserCodeGenerator {
	return &NumericUserCodeGenerator{
		UserCodeType: wicket.UserCodeTypesNumeric,
		RetryLimit:   5,
	}
}

// Generates the user code.
func (g *NumericUserCodeGenerator) Generate() string {
	return strconv.FormatInt(int64(rand.Int31n(1000000000-100000000)+100000000), 10)
}

func (g *NumericUserCodeGenerator) GetUserCodeType() string {
	return g.UserCodeType
}

func (g *NumericUserCodeGenerator) GetRetryLimit() int {
	return g.RetryLimit
}
