// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

// ConsentMessageKey derives the storage key for a consent answer from the
// subject identifier and the original authorize parameters. The interaction
// side records the answer and the authorize callback reads it back; both must
// derive the key through this single function so the two sides cannot drift.
//
// The key binds the full canonical parameter encoding: any difference in the
// parameter set recovered on either side — or an empty subject on one side
// only — produces a different key and the answer is simply not found. Callers
// are expected to pass the original authorize parameters (not a reparsed or
// augmented query) and the subject of an authenticated session.
func ConsentMessageKey(subjectId string, parameters url.Values) string {
	sum := sha256.Sum256([]byte(subjectId + "|" + parameters.Encode()))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
