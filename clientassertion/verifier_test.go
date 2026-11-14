// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket/replay"
)

func mustReject(t *testing.T, f *fixture, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("assertion accepted, want rejection")
	}
	if errors.Is(err, ErrAuthenticationUnavailable) {
		t.Fatalf("rejection reported as unavailable: %v", err)
	}
	if calls := f.registry.callCount(); calls != 0 {
		t.Fatalf("registry called %d times on a stateless rejection, want 0", calls)
	}
}

func TestVerifyAcceptsEverySupportedAlgorithm(t *testing.T) {
	for _, algorithm := range SupportedSigningAlgorithms() {
		t.Run(algorithm, func(t *testing.T) {
			f := newFixture(Options{})
			key := keyFor(t, algorithm, "k1")
			principal := Principal{ID: "client", Jwks: keySet(t, key)}
			if err := f.verify(principal, key.sign(t, algorithm, f.claims("client"))); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if calls := f.registry.callCount(); calls != 1 {
				t.Fatalf("registry called %d times, want 1", calls)
			}
		})
	}
}

func TestVerifyRejectsUnacceptableAlgorithms(t *testing.T) {
	rsaKey := newRsaKey(t, "")
	p256 := keyFor(t, "ES256", "")
	publicBytes, err := x509.MarshalPKIXPublicKey(rsaKey.private.Public())
	if err != nil {
		t.Fatal(err)
	}
	weak := newFreshRsaKey(t, "", 1024)

	cases := []struct {
		name      string
		options   Options
		key       testKey
		assertion func(f *fixture) string
	}{
		{"none without signature", Options{}, rsaKey, func(f *fixture) string { return unsignedAssertion("none", "", f.claims("client")) }},
		{"none with signature", Options{}, rsaKey, func(f *fixture) string { return unsignedAssertion("none", "AAAA", f.claims("client")) }},
		{"HS256 keyed with the public key", Options{}, rsaKey, func(f *fixture) string { return macAssertion(t, "HS256", publicBytes, f.claims("client")) }},
		{"HS384", Options{}, rsaKey, func(f *fixture) string { return macAssertion(t, "HS384", publicBytes, f.claims("client")) }},
		{"HS512", Options{}, rsaKey, func(f *fixture) string { return macAssertion(t, "HS512", publicBytes, f.claims("client")) }},
		{"unknown value", Options{}, rsaKey, func(f *fixture) string { return unsignedAssertion("XS256", "AAAA", f.claims("client")) }},
		{"empty value", Options{}, rsaKey, func(f *fixture) string { return unsignedAssertion("", "AAAA", f.claims("client")) }},
		{"RSA key under ES256", Options{}, rsaKey, func(f *fixture) string {
			return rsaKey.signAs(t, "ES256", "RS256", nil, f.claims("client"))
		}},
		{"P-256 key under ES384", Options{}, p256, func(f *fixture) string {
			return p256.signAs(t, "ES384", "ES384", nil, f.claims("client"))
		}},
		{"EC key under RS256", Options{}, p256, func(f *fixture) string {
			return p256.signAs(t, "RS256", "ES256", nil, f.claims("client"))
		}},
		{"1024 bit RSA key", Options{}, weak, func(f *fixture) string { return weak.sign(t, "RS256", f.claims("client")) }},
		{"outside the configured subset", Options{SigningAlgorithms: []string{"ES256"}}, rsaKey, func(f *fixture) string {
			return rsaKey.sign(t, "RS256", f.claims("client"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(tc.options)
			principal := Principal{ID: "client", Jwks: keySet(t, tc.key)}
			mustReject(t, f, f.verify(principal, tc.assertion(f)))
		})
	}

	t.Run("inside the configured subset", func(t *testing.T) {
		f := newFixture(Options{SigningAlgorithms: []string{"ES256"}})
		principal := Principal{ID: "client", Jwks: keySet(t, p256)}
		if err := f.verify(principal, p256.sign(t, "ES256", f.claims("client"))); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
}

func TestVerifyClaimRules(t *testing.T) {
	const skew = 60 * time.Second
	const lifetime = 5 * time.Minute
	key := keyFor(t, "ES256", "k1")
	principal := Principal{ID: "client", Jwks: keySet(t, key)}

	type mutate func(claims map[string]any, now time.Time)
	set := func(name string, value any) mutate {
		return func(claims map[string]any, _ time.Time) { claims[name] = value }
	}
	drop := func(name string) mutate {
		return func(claims map[string]any, _ time.Time) { delete(claims, name) }
	}
	at := func(name string, offset time.Duration) mutate {
		return func(claims map[string]any, now time.Time) { claims[name] = now.Add(offset).Unix() }
	}

	cases := []struct {
		name   string
		mutate mutate
		accept bool
	}{
		{"baseline", func(map[string]any, time.Time) {}, true},

		{"iss differs", set("iss", "other"), false},
		{"iss missing", drop("iss"), false},
		{"iss not a string", set("iss", 7), false},
		{"sub differs", set("sub", "other"), false},
		{"sub missing", drop("sub"), false},
		{"sub not a string", set("sub", []string{"client"}), false},

		{"aud string", set("aud", testAudience), true},
		{"aud single element array", set("aud", []string{testAudience}), true},
		{"aud two element array", set("aud", []string{testAudience, testAudience}), false},
		{"aud with a second audience", set("aud", []string{testAudience, "https://other.example"}), false},
		{"aud token endpoint", set("aud", testAudience+"/connect/token"), false},
		{"aud trailing slash", set("aud", testAudience+"/"), false},
		{"aud upper case", set("aud", strings.ToUpper(testAudience)), false},
		{"aud missing", drop("aud"), false},
		{"aud empty array", set("aud", []string{}), false},
		{"aud non string element", set("aud", []any{7}), false},
		{"aud number", set("aud", 7), false},

		{"exp missing", drop("exp"), false},
		{"exp at now minus skew", at("exp", -skew), false},
		{"exp one second inside", at("exp", -skew+time.Second), true},
		{"exp one second outside", at("exp", -skew-time.Second), false},
		{"exp at now plus skew", at("exp", skew), true},
		{"exp at the lifetime bound", at("exp", lifetime), true},
		{"exp one second over the lifetime bound", at("exp", lifetime+time.Second), false},
		{"exp string", set("exp", "1800000060"), false},
		{"exp negative", set("exp", -1), false},
		{"exp beyond year 9999", set("exp", int64(253402300800)), false},
		{"exp fractional", func(claims map[string]any, now time.Time) { claims["exp"] = float64(now.Unix()) + 30.5 }, true},

		{"nbf at now plus skew", at("nbf", skew), true},
		{"nbf one second later", at("nbf", skew+time.Second), false},
		{"nbf string", set("nbf", "soon"), false},

		{"iat at now plus skew", at("iat", skew), true},
		{"iat one second later", at("iat", skew+time.Second), false},
		{"iat at the age bound", at("iat", -(lifetime + skew)), true},
		{"iat one second older", at("iat", -(lifetime + skew + time.Second)), false},

		{"jti missing", drop("jti"), false},
		{"jti empty", set("jti", ""), false},
		{"jti not a string", set("jti", 7), false},
		{"jti 256 bytes", set("jti", strings.Repeat("a", 256)), true},
		{"jti 257 bytes", set("jti", strings.Repeat("a", 257)), false},

		{"unknown claim", set("extra", map[string]any{"a": 1}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(Options{ClockSkew: skew, MaxAssertionLifetime: lifetime})
			claims := f.claims("client")
			tc.mutate(claims, f.clock.Now())
			err := f.verify(principal, key.sign(t, "ES256", claims))
			if tc.accept {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if calls := f.registry.callCount(); calls != 1 {
					t.Fatalf("registry called %d times, want 1", calls)
				}
				return
			}
			mustReject(t, f, err)
		})
	}
}

func TestVerifyRejectsEveryAssertionWithoutAnIssuerIdentifier(t *testing.T) {
	f := newFixture(Options{})
	key := keyFor(t, "ES256", "k1")
	principal := Principal{ID: "client", Jwks: keySet(t, key)}
	claims := f.claims("client")
	claims["aud"] = ""
	err := f.verifier.Verify(context.Background(), principal, "", key.sign(t, "ES256", claims))
	mustReject(t, f, err)
}

func TestVerifyRegistersAnAcceptedAssertionOnce(t *testing.T) {
	const skew = 45 * time.Second
	key := keyFor(t, "ES256", "k1")
	principal := Principal{ID: "client", Jwks: keySet(t, key)}

	cases := []struct {
		name   string
		offset time.Duration
	}{
		{"exp in the future", 2 * time.Minute},
		{"exp already past but inside the skew", -30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(Options{ClockSkew: skew})
			now := f.clock.Now()
			claims := f.claims("client")
			claims["exp"] = now.Add(tc.offset).Unix()
			claims["jti"] = "one-time"
			if err := f.verify(principal, key.sign(t, "ES256", claims)); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			wantKey, err := replay.Key(replay.PurposeClientAssertion(), "client", "one-time")
			if err != nil {
				t.Fatal(err)
			}
			later := now.Add(tc.offset)
			if now.After(later) {
				later = now
			}
			wantExpiry := later.Add(skew)
			if f.registry.callCount() != 1 || f.registry.keys[0] != wantKey {
				t.Fatalf("registered %v, want exactly [%s]", f.registry.keys, wantKey)
			}
			if !f.registry.expires[0].Equal(wantExpiry) {
				t.Fatalf("registered until %s, want %s", f.registry.expires[0], wantExpiry)
			}
		})
	}
}

func TestVerifyRejectsAReplayedAssertion(t *testing.T) {
	f := newFixture(Options{})
	key := keyFor(t, "ES256", "k1")
	principal := Principal{ID: "client", Jwks: keySet(t, key)}
	assertion := key.sign(t, "ES256", f.claims("client"))
	if err := f.verify(principal, assertion); err != nil {
		t.Fatalf("first use: %v", err)
	}
	err := f.verify(principal, assertion)
	if err == nil || errors.Is(err, ErrAuthenticationUnavailable) {
		t.Fatalf("second use: got %v, want an ordinary rejection", err)
	}
}

func TestVerifyReportsARegistryFailureWithoutItsDetail(t *testing.T) {
	f := newFixture(Options{})
	f.registry.err = errors.New("boom-7f3a key=secret-handle")
	key := keyFor(t, "ES256", "k1")
	principal := Principal{ID: "client", Jwks: keySet(t, key)}
	claims := f.claims("client")
	claims["jti"] = "private-identifier"
	err := f.verify(principal, key.sign(t, "ES256", claims))
	if err != ErrAuthenticationUnavailable {
		t.Fatalf("got %v, want the sentinel itself", err)
	}
	if err.Error() != "client authentication temporarily unavailable" {
		t.Fatalf("sentinel text changed: %q", err.Error())
	}
	logs := f.logs.String()
	for _, secret := range []string{"boom-7f3a", "secret-handle", "private-identifier"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log leaks %q: %s", secret, logs)
		}
	}
	if !strings.Contains(logs, "registry_unavailable") {
		t.Fatalf("log misses the failure category: %s", logs)
	}
}

func TestVerifyNeverLogsTheAssertionOrItsIdentifier(t *testing.T) {
	f := newFixture(Options{})
	key := keyFor(t, "ES256", "k1")
	principal := Principal{ID: "client", Jwks: keySet(t, key)}
	claims := f.claims("client")
	claims["jti"] = "private-identifier"
	claims["aud"] = "https://wrong.example"
	assertion := key.sign(t, "ES256", claims)
	mustReject(t, f, f.verify(principal, assertion))
	logs := f.logs.String()
	for _, secret := range append(strings.Split(assertion, "."), "private-identifier") {
		if strings.Contains(logs, secret) {
			t.Fatalf("log leaks assertion material: %s", logs)
		}
	}
}

func TestVerifyHeaderRules(t *testing.T) {
	key := keyFor(t, "ES256", "k1")
	principal := Principal{ID: "client", Jwks: keySet(t, key)}
	for _, typ := range []string{"client-authentication+jwt", "JWT", "something-else"} {
		f := newFixture(Options{})
		if err := f.verify(principal, key.signAs(t, "ES256", "ES256", map[string]any{"typ": typ}, f.claims("client"))); err != nil {
			t.Fatalf("typ %q: %v", typ, err)
		}
	}
	f := newFixture(Options{})
	mustReject(t, f, f.verify(principal, key.signAs(t, "ES256", "ES256", map[string]any{"crit": []string{"exp"}, "exp": 1}, f.claims("client"))))
}

func TestVerifyStructureRules(t *testing.T) {
	key := keyFor(t, "ES256", "k1")
	principal := Principal{ID: "client", Jwks: keySet(t, key)}
	f := newFixture(Options{MaxAssertionBytes: 200})
	valid := key.sign(t, "ES256", f.claims("client"))
	if len(valid) <= 200 {
		t.Fatalf("test assertion too short: %d", len(valid))
	}
	mustReject(t, f, f.verify(principal, valid))

	f = newFixture(Options{})
	valid = key.sign(t, "ES256", f.claims("client"))
	segments := strings.Split(valid, ".")
	for name, assertion := range map[string]string{
		"two segments":       segments[0] + "." + segments[1],
		"four segments":      valid + ".AAAA",
		"empty signature":    segments[0] + "." + segments[1] + ".",
		"tampered payload":   segments[0] + "." + segments[1] + "AA." + segments[2],
		"tampered signature": segments[0] + "." + segments[1] + "." + encode([]byte("not a signature")),
		"empty":              "",
	} {
		g := newFixture(Options{})
		if err := g.verify(principal, assertion); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if g.registry.callCount() != 0 {
			t.Fatalf("%s: registry called", name)
		}
	}
}

func TestVerifyKeySelection(t *testing.T) {
	first := keyFor(t, "ES256", "k1")
	second := keyFor(t, "ES256", "k2")
	anonymous := testKey{private: first.private}

	t.Run("kid picks one of several keys", func(t *testing.T) {
		f := newFixture(Options{})
		principal := Principal{ID: "client", Jwks: keySet(t, first, second)}
		if err := f.verify(principal, second.sign(t, "ES256", f.claims("client"))); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
	t.Run("no kid and several keys", func(t *testing.T) {
		f := newFixture(Options{})
		principal := Principal{ID: "client", Jwks: keySet(t, first, second)}
		mustReject(t, f, f.verify(principal, anonymous.sign(t, "ES256", f.claims("client"))))
	})
	t.Run("no kid and one key", func(t *testing.T) {
		f := newFixture(Options{})
		principal := Principal{ID: "client", Jwks: keySet(t, first)}
		if err := f.verify(principal, anonymous.sign(t, "ES256", f.claims("client"))); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
	t.Run("unknown kid", func(t *testing.T) {
		f := newFixture(Options{})
		principal := Principal{ID: "client", Jwks: keySet(t, first)}
		mustReject(t, f, f.verify(principal, second.sign(t, "ES256", f.claims("client"))))
	})
	t.Run("key registered for another use", func(t *testing.T) {
		f := newFixture(Options{})
		member := first.jwk(t)
		member["use"] = "enc"
		document := `{"keys":[` + mustJson(t, member) + `]}`
		mustReject(t, f, f.verify(Principal{ID: "client", Jwks: document}, first.sign(t, "ES256", f.claims("client"))))
	})
	t.Run("key registered for another algorithm", func(t *testing.T) {
		f := newFixture(Options{})
		rsaKey := newRsaKey(t, "r1")
		member := rsaKey.jwk(t)
		member["alg"] = "PS256"
		document := `{"keys":[` + mustJson(t, member) + `]}`
		mustReject(t, f, f.verify(Principal{ID: "client", Jwks: document}, rsaKey.sign(t, "RS256", f.claims("client"))))
	})
	t.Run("both key registrations", func(t *testing.T) {
		f := newFixture(Options{})
		principal := Principal{ID: "client", Jwks: keySet(t, first), JwksUri: "https://client.example/jwks"}
		mustReject(t, f, f.verify(principal, first.sign(t, "ES256", f.claims("client"))))
	})
	t.Run("no key registration", func(t *testing.T) {
		f := newFixture(Options{})
		mustReject(t, f, f.verify(Principal{ID: "client"}, first.sign(t, "ES256", f.claims("client"))))
	})
	t.Run("malformed inline key set", func(t *testing.T) {
		f := newFixture(Options{})
		mustReject(t, f, f.verify(Principal{ID: "client", Jwks: "{not json"}, first.sign(t, "ES256", f.claims("client"))))
	})
}

func TestConstructorsTakeDefaultsFromANilOptionsSource(t *testing.T) {
	clock := newFakeClock()
	registry := &fakeRegistry{}
	verifier := NewVerifier(nil, NewKeySource(nil, clock, nil), registry, clock, nil)
	key := keyFor(t, "ES256", "k1")
	claims := map[string]any{"iss": "client", "sub": "client", "aud": testAudience, "exp": clock.Now().Add(time.Minute).Unix(), "jti": "a"}
	err := verifier.Verify(context.Background(), Principal{ID: "client", Jwks: keySet(t, key)}, testAudience, key.sign(t, "ES256", claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestConstructorsDoNotReadTheOptions(t *testing.T) {
	reads := 0
	source := func() Options { reads++; return Options{} }
	clock := newFakeClock()
	registry := &fakeRegistry{}
	NewVerifier(source, NewKeySource(source, clock, nil), registry, clock, nil)
	if reads != 0 || registry.callCount() != 0 {
		t.Fatalf("construction read the options %d times and called the registry %d times", reads, registry.callCount())
	}
}
