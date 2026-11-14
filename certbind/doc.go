// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package certbind implements the certificate thumbprint confirmation of RFC
// 8705 §3.1: an access token bound to a client certificate carries, under
// its cnf claim, the x5t#S256 member holding the base64url encoding (without
// padding) of the SHA-256 digest of the certificate's DER encoding. A
// protected resource accepts such a token only when the request presents
// that certificate.
//
// The package depends on the standard library only, so the token service,
// the userinfo endpoint and the JWT bearer handler share one algorithm.
package certbind
