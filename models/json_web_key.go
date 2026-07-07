// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"encoding/json"

	jwkpkg "github.com/lestrrat-go/jwx/v2/jwk"
)

type JsonWebKey struct {
	jwkpkg.Key
}

func (jwk *JsonWebKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(jwk.Key)
}

func (jwk *JsonWebKey) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &jwk.Key)
}
