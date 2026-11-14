// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package clientcert implements mutual TLS client authentication as defined
// by RFC 8705: the PKI method tls_client_auth, which trusts a certificate
// chained to a configured authority and matched against one registered
// subject attribute, and the self-signed method self_signed_tls_client_auth,
// which trusts a certificate registered by the client itself in its inline
// JWK Set.
//
// Where the client certificate comes from is a seam: CertificateSource. The
// default reads the certificates the peer presented on the TLS connection.
// No proxy header is trusted by this package; a host behind a TLS
// terminating proxy supplies its own source and owns that trust decision.
package clientcert
