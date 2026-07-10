// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package utils

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
)

func Sha256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func Sha512(value string) string {
	sum := sha512.Sum512([]byte(value))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TimeConstantCompare(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
