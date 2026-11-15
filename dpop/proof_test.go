// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"strings"
	"testing"
	"time"
)

const testEndpoint = "https://as.example/connect/token"

var testNow = time.Unix(1_800_000_000, 0)

// proofKey is a key a test client signs proofs with.
type proofKey struct {
	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
}

func newEcKey(t *testing.T, curve elliptic.Curve) proofKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return proofKey{ec: key}
}

func newRsaKey(t *testing.T, bits int) proofKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return proofKey{rsa: key}
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// publicJwk returns the public JWK members of the key.
func (k proofKey) publicJwk() map[string]any {
	if k.rsa != nil {
		e := big64(k.rsa.E)
		return map[string]any{"kty": "RSA", "n": b64(k.rsa.N.Bytes()), "e": b64(e)}
	}
	size := (k.ec.Curve.Params().BitSize + 7) / 8
	x := make([]byte, size)
	y := make([]byte, size)
	k.ec.X.FillBytes(x)
	k.ec.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "crv": k.ec.Curve.Params().Name, "x": b64(x), "y": b64(y)}
}

func big64(e int) []byte {
	var out []byte
	for e > 0 {
		out = append([]byte{byte(e & 0xff)}, out...)
		e >>= 8
	}
	return out
}

// sign builds a compact JWS over header and claims with the key, for alg.
func (k proofKey) sign(t *testing.T, alg string, header map[string]any, claims map[string]any) string {
	t.Helper()
	rawHeader, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	rawClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return k.signRaw(t, alg, rawHeader, rawClaims)
}

// signRaw builds a compact JWS over the exact header and payload bytes.
func (k proofKey) signRaw(t *testing.T, alg string, rawHeader []byte, rawClaims []byte) string {
	t.Helper()
	var err error
	input := b64(rawHeader) + "." + b64(rawClaims)
	var hash crypto.Hash
	switch alg[2:] {
	case "256":
		hash = crypto.SHA256
	case "384":
		hash = crypto.SHA384
	default:
		hash = crypto.SHA512
	}
	var digest []byte
	switch hash {
	case crypto.SHA256:
		sum := sha256.Sum256([]byte(input))
		digest = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384([]byte(input))
		digest = sum[:]
	default:
		sum := sha512.Sum512([]byte(input))
		digest = sum[:]
	}
	var signature []byte
	switch {
	case k.ec != nil:
		r, s, err := ecdsa.Sign(rand.Reader, k.ec, digest)
		if err != nil {
			t.Fatal(err)
		}
		size := (k.ec.Curve.Params().BitSize + 7) / 8
		signature = make([]byte, 2*size)
		r.FillBytes(signature[:size])
		s.FillBytes(signature[size:])
	case strings.HasPrefix(alg, "PS"):
		signature, err = rsa.SignPSS(rand.Reader, k.rsa, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default:
		signature, err = rsa.SignPKCS1v15(rand.Reader, k.rsa, hash, digest)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(signature)
}

func validHeader(k proofKey, alg string) map[string]any {
	return map[string]any{"typ": "dpop+jwt", "alg": alg, "jwk": k.publicJwk()}
}

func validClaims() map[string]any {
	return map[string]any{
		"jti": "proof-1",
		"htm": "POST",
		"htu": testEndpoint,
		"iat": testNow.Unix(),
	}
}

func TestVerifyAcceptsValidProofs(t *testing.T) {
	t.Parallel()
	verifier := NewVerifier(Options{})
	cases := map[string]struct {
		key proofKey
		alg string
	}{
		"ES256": {newEcKey(t, elliptic.P256()), "ES256"},
		"ES384": {newEcKey(t, elliptic.P384()), "ES384"},
		"ES512": {newEcKey(t, elliptic.P521()), "ES512"},
		"RS256": {newRsaKey(t, 2048), "RS256"},
		"PS256": {newRsaKey(t, 2048), "PS256"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			proof := tc.key.sign(t, tc.alg, validHeader(tc.key, tc.alg), validClaims())
			got, err := verifier.Verify([]string{proof}, "POST", testEndpoint, testNow)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got.JwtId != "proof-1" || !got.IssuedAt.Equal(testNow) || got.Thumbprint == "" {
				t.Fatalf("proof = %+v", got)
			}
		})
	}
}

func TestVerifyThumbprintIsTheProofKeys(t *testing.T) {
	t.Parallel()
	key := newEcKey(t, elliptic.P256())
	proof := key.sign(t, "ES256", validHeader(key, "ES256"), validClaims())
	got, err := NewVerifier(Options{}).Verify([]string{proof}, "POST", testEndpoint, testNow)
	if err != nil {
		t.Fatal(err)
	}
	members := key.publicJwk()
	canonical := `{"crv":"P-256","kty":"EC","x":"` + members["x"].(string) + `","y":"` + members["y"].(string) + `"}`
	digest := sha256.Sum256([]byte(canonical))
	if want := b64(digest[:]); got.Thumbprint != want {
		t.Fatalf("thumbprint %q, want %q", got.Thumbprint, want)
	}
}

func TestVerifyRejects(t *testing.T) {
	t.Parallel()
	key := newEcKey(t, elliptic.P256())
	other := newEcKey(t, elliptic.P256())
	rsaKey := newRsaKey(t, 2048)
	smallRsa := newRsaKey(t, 1024)

	with := func(base map[string]any, name string, value any) map[string]any {
		out := maps.Clone(base)
		if value == nil {
			delete(out, name)
		} else {
			out[name] = value
		}
		return out
	}
	jwkWith := func(name string, value any) map[string]any {
		members := key.publicJwk()
		members[name] = value
		return members
	}
	good := key.sign(t, "ES256", validHeader(key, "ES256"), validClaims())
	segments := strings.Split(good, ".")
	unsignedHeader := func(header map[string]any) string {
		raw, _ := json.Marshal(header)
		return b64(raw) + "." + segments[1] + "." + segments[2]
	}

	cases := map[string]struct {
		values   []string
		method   string
		endpoint string
	}{
		"no value":                {values: []string{}},
		"two header fields":       {values: []string{good, good}},
		"empty value":             {values: []string{""}},
		"two segments":            {values: []string{segments[0] + "." + segments[1]}},
		"four segments":           {values: []string{good + ".x"}},
		"empty signature":         {values: []string{segments[0] + "." + segments[1] + "."}},
		"header not base64":       {values: []string{"%%%." + segments[1] + "." + segments[2]}},
		"header not JSON":         {values: []string{b64([]byte("[1]")) + "." + segments[1] + "." + segments[2]}},
		"oversized":               {values: []string{strings.Repeat("a", maxProofBytes) + "." + segments[1] + "." + segments[2]}},
		"typ missing":             {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "typ", nil), validClaims())}},
		"typ jwt":                 {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "typ", "JWT"), validClaims())}},
		"alg none":                {values: []string{unsignedHeader(with(validHeader(key, "ES256"), "alg", "none"))}},
		"alg HS256":               {values: []string{unsignedHeader(with(validHeader(key, "ES256"), "alg", "HS256"))}},
		"alg not configured":      {values: []string{rsaKey.sign(t, "RS256", validHeader(rsaKey, "RS256"), validClaims())}, endpoint: "es-only"},
		"jwk missing":             {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "jwk", nil), validClaims())}},
		"jwk not an object":       {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "jwk", "key"), validClaims())}},
		"jwk carries d":           {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "jwk", jwkWith("d", "AAAA")), validClaims())}},
		"jwk carries k":           {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "jwk", jwkWith("k", "AAAA")), validClaims())}},
		"jwk carries p":           {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "jwk", jwkWith("p", "AAAA")), validClaims())}},
		"jwk carries oth":         {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "jwk", jwkWith("oth", []any{})), validClaims())}},
		"jwk of another type":     {values: []string{key.sign(t, "ES256", validHeader(rsaKey, "ES256"), validClaims())}},
		"jwk type for alg":        {values: []string{unsignedHeader(with(validHeader(key, "ES256"), "alg", "RS256"))}},
		"jwk curve for alg":       {values: []string{unsignedHeader(with(validHeader(key, "ES256"), "alg", "ES384"))}},
		"jwk point off the curve": {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "jwk", map[string]any{"kty": "EC", "crv": "P-256", "x": b64(make([]byte, 32)), "y": b64(append(make([]byte, 31), 1))}), validClaims())}},
		"rsa key too small":       {values: []string{smallRsa.sign(t, "RS256", validHeader(smallRsa, "RS256"), validClaims())}},
		"crit present":            {values: []string{key.sign(t, "ES256", with(validHeader(key, "ES256"), "crit", []string{"exp"}), validClaims())}},
		"signed by another":       {values: []string{other.sign(t, "ES256", validHeader(key, "ES256"), validClaims())}},
		"jti missing":             {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "jti", nil))}},
		"jti empty":               {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "jti", ""))}},
		"jti not a string":        {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "jti", 7))}},
		"jti too long":            {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "jti", strings.Repeat("j", maxProofIdBytes+1)))}},
		"htm missing":             {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htm", nil))}},
		"htm other method":        {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htm", "GET"))}},
		"htm other case":          {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htm", "post"))}},
		"htu missing":             {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htu", nil))}},
		"htu other path":          {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htu", "https://as.example/connect/userinfo"))}},
		"htu other host":          {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htu", "https://other.example/connect/token"))}},
		"htu other scheme":        {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htu", "http://as.example/connect/token"))}},
		"htu other port":          {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htu", "https://as.example:8443/connect/token"))}},
		"htu percent encoded":     {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htu", "https://as.example/connect/%74oken"))}},
		"htu relative":            {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "htu", "/connect/token"))}},
		"iat missing":             {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "iat", nil))}},
		"iat a string":            {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "iat", "1800000000"))}},
		"iat too old":             {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "iat", testNow.Add(-121*time.Second).Unix()))}},
		"iat in the future":       {values: []string{key.sign(t, "ES256", validHeader(key, "ES256"), with(validClaims(), "iat", testNow.Add(61*time.Second).Unix()))}},
		"other method":            {values: []string{good}, method: "PUT"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := Options{}
			if tc.endpoint == "es-only" {
				options.SigningAlgorithms = []string{"ES256"}
				tc.endpoint = ""
			}
			method := tc.method
			if method == "" {
				method = "POST"
			}
			endpoint := tc.endpoint
			if endpoint == "" {
				endpoint = testEndpoint
			}
			_, err := NewVerifier(options).Verify(tc.values, method, endpoint, testNow)
			if !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("err = %v, want ErrInvalidProof", err)
			}
		})
	}
}

// rsaJwk returns an RSA public JWK with the given modulus and exponent.
func rsaJwk(modulus *big.Int, exponent int) map[string]any {
	return map[string]any{"kty": "RSA", "n": b64(modulus.Bytes()), "e": b64(big64(exponent))}
}

func TestVerifyRejectsUnreasonableRsaKeys(t *testing.T) {
	t.Parallel()
	key := newRsaKey(t, 2048)
	// A modulus above 8192 bits; it need not be a real key since the proof
	// must be refused before the signature is checked.
	huge := new(big.Int).Lsh(big.NewInt(1), 8200)
	huge.Add(huge, big.NewInt(1))
	cases := map[string]map[string]any{
		"modulus above 8192 bits": rsaJwk(huge, 65537),
		"even exponent":           rsaJwk(key.rsa.N, 65536),
		"exponent above 2^31-1":   rsaJwk(key.rsa.N, 1<<31+1),
		"exponent below 3":        rsaJwk(key.rsa.N, 1),
	}
	for name, jwk := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			header := map[string]any{"typ": "dpop+jwt", "alg": "RS256", "jwk": jwk}
			_, err := NewVerifier(Options{}).Verify([]string{key.sign(t, "RS256", header, validClaims())}, "POST", testEndpoint, testNow)
			if !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("err = %v, want ErrInvalidProof", err)
			}
			if strings.HasSuffix(err.Error(), ": signature") {
				t.Fatalf("the key reached signature verification: %v", err)
			}
		})
	}
}

func TestVerifyRejectsTrailingDataAfterClaims(t *testing.T) {
	t.Parallel()
	key := newEcKey(t, elliptic.P256())
	rawHeader, _ := json.Marshal(validHeader(key, "ES256"))
	rawClaims, _ := json.Marshal(validClaims())
	verifier := NewVerifier(Options{})
	if _, err := verifier.Verify([]string{key.signRaw(t, "ES256", rawHeader, rawClaims)}, "POST", testEndpoint, testNow); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, trailer := range map[string]string{"second object": `{"jti":"x"}`, "garbage": "garbage"} {
		payload := append(append([]byte(nil), rawClaims...), trailer...)
		_, err := verifier.Verify([]string{key.signRaw(t, "ES256", rawHeader, payload)}, "POST", testEndpoint, testNow)
		if !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("%s: err = %v, want ErrInvalidProof", name, err)
		}
	}
}

func TestVerifyIatWindowEdges(t *testing.T) {
	t.Parallel()
	key := newEcKey(t, elliptic.P256())
	verifier := NewVerifier(Options{ProofLifetime: 30 * time.Second, ClockSkew: 5 * time.Second})
	for name, tc := range map[string]struct {
		iat    time.Time
		accept bool
	}{
		"oldest accepted":  {testNow.Add(-35 * time.Second), true},
		"one second older": {testNow.Add(-36 * time.Second), false},
		"newest accepted":  {testNow.Add(5 * time.Second), true},
		"one second newer": {testNow.Add(6 * time.Second), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims()
			claims["iat"] = tc.iat.Unix()
			_, err := verifier.Verify([]string{key.sign(t, "ES256", validHeader(key, "ES256"), claims)}, "POST", testEndpoint, testNow)
			if (err == nil) != tc.accept {
				t.Fatalf("err = %v, accept = %v", err, tc.accept)
			}
		})
	}
}

func TestVerifyHtuNormalization(t *testing.T) {
	t.Parallel()
	key := newEcKey(t, elliptic.P256())
	verifier := NewVerifier(Options{})
	for name, htu := range map[string]string{
		"exact":                "https://as.example/connect/token",
		"upper case scheme":    "HTTPS://as.example/connect/token",
		"upper case host":      "https://AS.Example/connect/token",
		"default port":         "https://as.example:443/connect/token",
		"query and fragment":   "https://as.example/connect/token?a=b#c",
		"typ in another case":  "https://as.example/connect/token",
		"empty query fragment": "https://as.example/connect/token?#",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			header := validHeader(key, "ES256")
			if name == "typ in another case" {
				header["typ"] = "DPoP+JWT"
			}
			claims := validClaims()
			claims["htu"] = htu
			if _, err := verifier.Verify([]string{key.sign(t, "ES256", header, claims)}, "POST", testEndpoint, testNow); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
	// The expected side is normalized the same way.
	claims := validClaims()
	claims["htu"] = "http://as.example/connect/token"
	if _, err := verifier.Verify([]string{key.sign(t, "ES256", validHeader(key, "ES256"), claims)}, "POST", "http://as.example:80/connect/token", testNow); err != nil {
		t.Fatalf("default http port on the expected side: %v", err)
	}
}

func TestVerifyIgnoresNonceAndAth(t *testing.T) {
	t.Parallel()
	key := newEcKey(t, elliptic.P256())
	claims := validClaims()
	claims["nonce"] = 12
	claims["ath"] = "anything"
	if _, err := NewVerifier(Options{}).Verify([]string{key.sign(t, "ES256", validHeader(key, "ES256"), claims)}, "POST", testEndpoint, testNow); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyReadsTheNonceOnlyWhenRequired(t *testing.T) {
	t.Parallel()
	key := newEcKey(t, elliptic.P256())
	proofWith := func(nonce any, present bool) []string {
		claims := validClaims()
		if present {
			claims["nonce"] = nonce
		}
		return []string{key.sign(t, "ES256", validHeader(key, "ES256"), claims)}
	}
	required := NewVerifier(Options{RequireNonce: true})

	proof, err := required.Verify(proofWith("server-nonce", true), "POST", testEndpoint, testNow)
	if err != nil || proof.Nonce != "server-nonce" {
		t.Fatalf("nonce %q err %v", proof.Nonce, err)
	}
	proof, err = required.Verify(proofWith(nil, false), "POST", testEndpoint, testNow)
	if err != nil || proof.Nonce != "" {
		t.Fatalf("absent nonce: %q err %v", proof.Nonce, err)
	}
	if _, err := required.Verify(proofWith(strings.Repeat("n", 512), true), "POST", testEndpoint, testNow); err != nil {
		t.Fatalf("512 byte nonce: %v", err)
	}
	for name, nonce := range map[string]any{
		"empty":     "",
		"number":    12,
		"null":      nil,
		"object":    map[string]any{},
		"too long":  strings.Repeat("n", 513),
		"array":     []any{"n"},
		"boolean":   true,
		"long utf8": strings.Repeat("ä", 257),
	} {
		if _, err := required.Verify(proofWith(nonce, true), "POST", testEndpoint, testNow); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("%s: err %v, want ErrInvalidProof", name, err)
		}
	}

	proof, err = NewVerifier(Options{}).Verify(proofWith("server-nonce", true), "POST", testEndpoint, testNow)
	if err != nil || proof.Nonce != "" {
		t.Fatalf("nonce read although not required: %q err %v", proof.Nonce, err)
	}
}
