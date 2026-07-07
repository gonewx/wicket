// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"sort"
	"strings"
)

// Compares resource_type strings, where the order of space-delimited values is insignificant.
// This is to handle the fact that the order of multi-valued response_type lists is
// insignificant, per the <see href="https://tools.ietf.org/html/rfc6749#section-3.1.1">OAuth2 spec</see>
// and the
// (<see href="http://openid.net/specs/oauth-v2-multiple-response-types-1_0-03.html#terminology">OAuth
// 2.0 Multiple Response Type Encoding Practices draft </see>).
type ResponseTypeEqualityComparer struct {
}

func (c *ResponseTypeEqualityComparer) Equal(x, y string) bool {
	if x == y {
		return true
	}

	if len(x) != len(y) {
		return false
	}

	xValues := strings.Split(x, " ")
	yValues := strings.Split(y, " ")
	if len(xValues) != len(yValues) {
		return false
	}

	sort.Strings(xValues)
	sort.Strings(yValues)

	for i := range xValues {
		if xValues[i] != yValues[i] {
			return false
		}
	}
	return true
}
