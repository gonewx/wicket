// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package oidcverify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func (v *verifier) Verify(ctx context.Context, idToken string) (*VerifiedToken, error) {
	return v.verify(ctx, idToken, "")
}

func (v *verifier) VerifyWithNonce(ctx context.Context, idToken, nonce string) (*VerifiedToken, error) {
	return v.verify(ctx, idToken, nonce)
}

func (v *verifier) verify(ctx context.Context, idToken, nonce string) (*VerifiedToken, error) {
	msg, err := jws.Parse([]byte(idToken))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedToken, err)
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, ErrMalformedToken
	}

	alg, ok := sigs[0].ProtectedHeaders().Algorithm()
	if !ok || alg.String() != jwa.RS256().String() {
		algStr := "none"
		if ok {
			algStr = alg.String()
		}
		return nil, fmt.Errorf("%w: got %s", ErrInvalidAlgorithm, algStr)
	}

	kid, _ := sigs[0].ProtectedHeaders().KeyID()

	set, err := v.resolveKeySet(ctx, kid)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse([]byte(idToken),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(v.config.Issuer),
		jwt.WithAudience(v.config.Audience),
		jwt.WithClock(v.clock),
		jwt.WithAcceptableSkew(v.config.ClockSkew),
		jwt.WithTruncation(time.Second),
	)
	if err != nil {
		return nil, mapParseError(err)
	}

	if v.config.NonceRequired || nonce != "" {
		var tokenNonce string
		if err := token.Get("nonce", &tokenNonce); err != nil || tokenNonce == "" {
			return nil, ErrMissingNonce
		}
		if nonce != "" && tokenNonce != nonce {
			return nil, fmt.Errorf("%w: expected %q", ErrInvalidNonce, nonce)
		}
	}

	return projectToken(token)
}

func (v *verifier) resolveKeySet(ctx context.Context, kid string) (jwk.Set, error) {
	set, err := v.cache.Lookup(ctx, v.config.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyNotFound, err)
	}

	if kid != "" {
		if _, found := set.LookupKeyID(kid); found {
			return set, nil
		}
		set, err = v.cache.Refresh(ctx, v.config.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyNotFound, err)
		}
		if _, found := set.LookupKeyID(kid); !found {
			return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
		}
		return set, nil
	}

	if set.Len() == 1 {
		return set, nil
	}
	return nil, fmt.Errorf("%w: no kid in token and JWKS has multiple keys", ErrKeyNotFound)
}

func mapParseError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, `"exp"`), strings.Contains(msg, `"nbf"`), strings.Contains(msg, `"iat"`):
		return fmt.Errorf("%w: %v", ErrTokenExpired, err)
	case strings.Contains(msg, `"iss"`):
		return fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
	case strings.Contains(msg, `"aud"`):
		return fmt.Errorf("%w: %v", ErrInvalidAudience, err)
	default:
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
}

func projectToken(token jwt.Token) (*VerifiedToken, error) {
	sub, _ := token.Subject()
	if sub == "" {
		return nil, ErrMalformedToken
	}
	iss, _ := token.Issuer()
	aud, _ := token.Audience()

	vt := &VerifiedToken{
		Subject:  sub,
		Issuer:   iss,
		Audience: aud,
	}

	var email string
	if err := token.Get("email", &email); err == nil {
		vt.Email = email
	}

	var emailVerified bool
	if err := token.Get("email_verified", &emailVerified); err == nil {
		vt.EmailVerified = emailVerified
	} else {
		var evStr string
		if err := token.Get("email_verified", &evStr); err == nil {
			vt.EmailVerified = evStr == "true"
		}
	}

	return vt, nil
}
