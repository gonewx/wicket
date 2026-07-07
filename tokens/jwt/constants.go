// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package jwt

import "regexp"

const (
	JweSegmentCount    int = 5
	JwsSegmentCount    int = 3
	MaxJwtSegmentCount int = 5

	JsonCompactSerializationRegex = `^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$`
	JweCompactSerializationRegex  = `^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`
)

var (
	RegexJws = regexp.MustCompile(JsonCompactSerializationRegex)
	RegexJwe = regexp.MustCompile(JweCompactSerializationRegex)
)

const (
	HeaderType = "JWT"
)
