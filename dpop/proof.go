// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// ProofType is the only accepted typ header value of a proof. It is compared
// without regard to case.
const ProofType = "dpop+jwt"

// ErrInvalidProof reports a proof that failed a stateless check. The wrapped
// text names the failed check for logs; it is never sent to the client.
var ErrInvalidProof = errors.New("dpop: invalid proof")

// privateKeyMembers are JWK members that only private or symmetric keys
// carry. A proof header jwk holding any of them is refused.
var privateKeyMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// Proof is what an accepted proof contributes to the request.
type Proof struct {
	// Thumbprint is the RFC 7638 SHA-256 thumbprint of the proof public key.
	Thumbprint string
	// JwtId is the jti claim.
	JwtId string
	// IssuedAt is the iat claim.
	IssuedAt time.Time
}

// Verifier runs the stateless checks of a proof.
type Verifier struct {
	options Options
}

// NewVerifier returns a verifier for options; zero fields take their
// defaults.
func NewVerifier(options Options) *Verifier {
	return &Verifier{options: options.withDefaults()}
}

// Verify checks the DPoP header values of one request. values holds every
// DPoP header field of the request, method is the request method, endpoint
// is the URI the request was addressed to and now is the current instant.
//
// Exactly one header field holding one compact JWS is accepted. The
// protected header must carry typ dpop+jwt, a configured alg, and a public
// jwk of the key type alg names, and no crit; the signature must verify with
// that jwk; the claims must carry jti (at most 256 bytes), htm equal to
// method, htu naming endpoint, and an iat no older than the proof lifetime
// and no newer than now, both widened by the clock skew. Any failure yields
// an error matching ErrInvalidProof. The nonce and ath claims are not judged.
func (v *Verifier) Verify(values []string, method string, endpoint string, now time.Time) (Proof, error) {
	if len(values) != 1 {
		return Proof{}, invalid("not exactly one proof")
	}
	proof := values[0]
	if proof == "" || len(proof) > maxProofBytes {
		return Proof{}, invalid("proof size")
	}
	segments := strings.Split(proof, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return Proof{}, invalid("not a compact JWS")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return Proof{}, invalid("header encoding")
	}
	if _, err := base64.RawURLEncoding.DecodeString(segments[1]); err != nil {
		return Proof{}, invalid("payload encoding")
	}
	if _, err := base64.RawURLEncoding.DecodeString(segments[2]); err != nil {
		return Proof{}, invalid("signature encoding")
	}

	algorithm, key, err := v.checkHeader(rawHeader)
	if err != nil {
		return Proof{}, err
	}
	publicKey, err := publicKeyFor(algorithm.String(), key)
	if err != nil {
		return Proof{}, err
	}
	payload, err := jws.Verify([]byte(proof), jws.WithKey(algorithm, publicKey))
	if err != nil {
		return Proof{}, invalid("signature")
	}
	thumbprint, err := Thumbprint(key)
	if err != nil {
		return Proof{}, invalid("thumbprint")
	}

	identifier, issuedAt, err := v.checkClaims(payload, method, endpoint, now)
	if err != nil {
		return Proof{}, err
	}
	return Proof{Thumbprint: thumbprint, JwtId: identifier, IssuedAt: issuedAt}, nil
}

// checkHeader judges the protected header and returns the signature
// algorithm and the public key it names.
func (v *Verifier) checkHeader(rawHeader []byte) (jwa.SignatureAlgorithm, jwk.Key, error) {
	var header map[string]json.RawMessage
	if err := json.Unmarshal(rawHeader, &header); err != nil || header == nil {
		return jwa.SignatureAlgorithm{}, nil, invalid("header is not a JSON object")
	}
	if _, ok := header["crit"]; ok {
		return jwa.SignatureAlgorithm{}, nil, invalid("crit header")
	}
	typ, ok := stringMember(header["typ"])
	if !ok || !strings.EqualFold(typ, ProofType) {
		return jwa.SignatureAlgorithm{}, nil, invalid("typ")
	}
	name, ok := stringMember(header["alg"])
	if !ok || !slices.Contains(v.options.SigningAlgorithms, name) {
		return jwa.SignatureAlgorithm{}, nil, invalid("alg")
	}
	algorithm, known := jwa.LookupSignatureAlgorithm(name)
	if !known {
		return jwa.SignatureAlgorithm{}, nil, invalid("alg")
	}

	rawKey := header["jwk"]
	var members map[string]json.RawMessage
	if len(rawKey) == 0 || rawKey[0] != '{' || json.Unmarshal(rawKey, &members) != nil || members == nil {
		return jwa.SignatureAlgorithm{}, nil, invalid("jwk missing or not an object")
	}
	for _, member := range privateKeyMembers {
		if _, ok := members[member]; ok {
			return jwa.SignatureAlgorithm{}, nil, invalid("jwk carries private key material")
		}
	}
	key, err := jwk.ParseKey(rawKey)
	if err != nil {
		return jwa.SignatureAlgorithm{}, nil, invalid("jwk unreadable")
	}
	return algorithm, key, nil
}

// publicKeyFor exports key and checks that it is a public key of the type
// and size algorithm requires. An RSA key needs a modulus of 2048 to 8192
// bits and an odd public exponent from 3 to 2^31-1, which bounds the work an
// unauthenticated proof can cause.
func publicKeyFor(algorithm string, key jwk.Key) (any, error) {
	var raw any
	if err := jwk.Export(key, &raw); err != nil {
		return nil, invalid("jwk unreadable")
	}
	switch {
	case strings.HasPrefix(algorithm, "RS"), strings.HasPrefix(algorithm, "PS"):
		public, ok := raw.(*rsa.PublicKey)
		if !ok || public.N == nil || public.N.BitLen() < minRsaModulusBits || public.N.BitLen() > maxRsaModulusBits ||
			public.E < 3 || public.E > maxRsaPublicExponent || public.E%2 == 0 {
			return nil, invalid("jwk does not match alg")
		}
		return public, nil
	case strings.HasPrefix(algorithm, "ES"):
		public, ok := raw.(*ecdsa.PublicKey)
		if !ok || public.Curve == nil || public.Curve != curveFor(algorithm) {
			return nil, invalid("jwk does not match alg")
		}
		return public, nil
	default:
		return nil, invalid("alg")
	}
}

func curveFor(algorithm string) elliptic.Curve {
	switch algorithm {
	case "ES256":
		return elliptic.P256()
	case "ES384":
		return elliptic.P384()
	case "ES512":
		return elliptic.P521()
	default:
		return nil
	}
}

// checkClaims judges the claims of a verified proof and returns its jti and
// iat.
func (v *Verifier) checkClaims(payload []byte, method string, endpoint string, now time.Time) (string, time.Time, error) {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil || claims == nil {
		return "", time.Time{}, invalid("payload is not a JSON object")
	}

	identifier, ok := stringMember(claims["jti"])
	if !ok || identifier == "" || len(identifier) > maxProofIdBytes {
		return "", time.Time{}, invalid("jti")
	}
	htm, ok := stringMember(claims["htm"])
	if !ok || htm != method {
		return "", time.Time{}, invalid("htm")
	}
	htu, ok := stringMember(claims["htu"])
	if !ok || !sameTarget(htu, endpoint) {
		return "", time.Time{}, invalid("htu")
	}
	issuedAt, ok := numericDate(claims["iat"])
	if !ok {
		return "", time.Time{}, invalid("iat")
	}
	skew := v.options.ClockSkew
	if issuedAt.Before(now.Add(-v.options.ProofLifetime - skew)) {
		return "", time.Time{}, invalid("iat too old")
	}
	if issuedAt.After(now.Add(skew)) {
		return "", time.Time{}, invalid("iat in the future")
	}
	return identifier, issuedAt, nil
}

// sameTarget reports whether the htu claim names endpoint. Both are parsed as
// URLs; the scheme and host compare in lower case, a default port is
// dropped, query and fragment are ignored, and the escaped paths compare
// byte for byte. Nothing else is normalized.
func sameTarget(htu string, endpoint string) bool {
	claimed, ok := targetOf(htu)
	if !ok {
		return false
	}
	expected, ok := targetOf(endpoint)
	return ok && claimed == expected
}

type target struct {
	scheme string
	host   string
	path   string
}

func targetOf(raw string) (target, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return target{}, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return target{scheme: scheme, host: host, path: parsed.EscapedPath()}, true
}

// stringMember reads a member that has to be a JSON string.
func stringMember(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// numericDate reads a NumericDate claim: a finite, non-negative JSON number
// within the representable range. Fractions are cut off towards the earlier
// second.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	if len(raw) == 0 || raw[0] == '"' {
		return time.Time{}, false
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return time.Time{}, false
	}
	seconds, err := number.Float64()
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > maxNumericDateSeconds {
		return time.Time{}, false
	}
	return time.Unix(int64(math.Floor(seconds)), 0), true
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidProof, reason)
}
