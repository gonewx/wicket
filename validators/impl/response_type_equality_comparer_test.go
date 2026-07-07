// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for ResponseTypeEqualityComparer
// Some of these are pretty fundamental equality checks, but the purpose here is to ensure the
// important property: that the order is insignificant when multiple values are
// sent in a space-delimited string.  We want to ensure that property holds and at the same time
// the basic equality function works as well.
func TestResponseTypeEqualityComparison(t *testing.T) {
	a := require.New(t)
	tests := []struct {
		name string
		x, y string
	}{
		{
			name: "Both_empty",
			x:    "",
			y:    "",
		},
		{
			name: "Left_empty_other_not",
			x:    "token",
			y:    "",
		},
		{
			name: "Right_empty_other_not",
			x:    "",
			y:    "token",
		},
		{
			name: "token_token",
			x:    "token",
			y:    "token",
		},
		{
			name: "id_token_id_token",
			x:    "id_token",
			y:    "id_token",
		},
		{
			name: "id_token_token",
			x:    "id_token",
			y:    "token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := &ResponseTypeEqualityComparer{}
			result := comparer.Equal(tt.x, tt.y)

			expected := tt.x == tt.y

			a.Equal(expected, result)
		})
	}
}

// These tests ensure the property demanded by the
// <see href="https://tools.ietf.org/html/rfc6749#section-3.1.1">OAuth2 spec</see>
// where, in a space-delimited list of values, the order is not important.
func TestResponseTypeEqualityComparisonMultipleValue(t *testing.T) {
	a := require.New(t)
	tests := []struct {
		name     string
		x, y     string
		expected bool
	}{
		{
			name:     "id_token_token_both_ways",
			x:        "id_token token",
			y:        "token id_token",
			expected: true,
		},
		{
			name:     "code_id_token_both_ways",
			x:        "code id_token",
			y:        "id_token code",
			expected: true,
		},
		{
			name:     "code_token_both_ways",
			x:        "code token",
			y:        "token code",
			expected: true,
		},
		{
			name:     "code_id_token_token_combo1",
			x:        "code id_token token",
			y:        "id_token code token",
			expected: true,
		},
		{
			name:     "code_id_token_token_combo2",
			x:        "code id_token token",
			y:        "token id_token code",
			expected: true,
		},
		{
			name:     "code_id_token_token_missing_code",
			x:        "code id_token token",
			y:        "id_token token",
			expected: false,
		},
		{
			name:     "code_id_token_token_missing_code_and_token",
			x:        "code id_token token",
			y:        "id_token",
			expected: false,
		},
		{
			name:     "Totally_different_words",
			x:        "blerg smoo",
			y:        "token code",
			expected: false,
		},
		{
			name:     "Same_length_different_count",
			x:        "code id_token token",
			y:        "tokenizer bleegerfi",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := &ResponseTypeEqualityComparer{}
			result := comparer.Equal(tt.x, tt.y)

			a.Equal(tt.expected, result)
		})
	}
}
