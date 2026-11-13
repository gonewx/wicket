// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrInvalidKeyInput reports that Key was given a Purpose other than the two
// defined ones, an empty qualifier or an empty jti.
var ErrInvalidKeyInput = errors.New("replay: invalid key input")

// keyDomain separates registry keys from any other SHA-256 use and carries
// the encoding version.
const keyDomain = "wicket.replay.v1"

const (
	purposeCodeClientAssertion byte = 0x01
	purposeCodeDPoPProof       byte = 0x02
)

// Purpose names what a one-time identifier belongs to. The set is closed:
// the only usable values come from PurposeClientAssertion and
// PurposeDPoPProof. The zero value is not a purpose and Key rejects it.
type Purpose struct {
	code byte
}

// PurposeClientAssertion is the purpose of a client assertion jti. Its
// qualifier is the client id.
func PurposeClientAssertion() Purpose {
	return Purpose{code: purposeCodeClientAssertion}
}

// PurposeDPoPProof is the purpose of a DPoP proof jti. Its qualifier is the
// thumbprint of the proof's public key.
func PurposeDPoPProof() Purpose {
	return Purpose{code: purposeCodeDPoPProof}
}

// Key derives the registry key for a one-time identifier. It is the only
// source of registry keys; callers never assemble one themselves.
//
// The digest input is the domain prefix, the purpose code, then qualifier and
// jti each preceded by its byte length as an 8-byte big-endian integer. The
// length prefixes keep ("ab", "c") apart from ("a", "bc"), and the purpose
// code keeps the two purposes apart. Qualifier and jti are opaque bytes:
// nothing is trimmed, case-folded or normalized. The result is the SHA-256
// digest as 64 lowercase hexadecimal characters.
//
// Key returns "" and an error matching ErrInvalidKeyInput for a purpose that
// is not one of the two defined values, an empty qualifier or an empty jti.
// The error never contains the qualifier or the jti.
func Key(purpose Purpose, qualifier, jti string) (string, error) {
	if purpose.code != purposeCodeClientAssertion && purpose.code != purposeCodeDPoPProof {
		return "", fmt.Errorf("%w: unknown purpose", ErrInvalidKeyInput)
	}
	if qualifier == "" {
		return "", fmt.Errorf("%w: empty qualifier", ErrInvalidKeyInput)
	}
	if jti == "" {
		return "", fmt.Errorf("%w: empty jti", ErrInvalidKeyInput)
	}

	preimage := make([]byte, 0, len(keyDomain)+1+8+len(qualifier)+8+len(jti))
	preimage = append(preimage, keyDomain...)
	preimage = append(preimage, purpose.code)
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(len(qualifier)))
	preimage = append(preimage, qualifier...)
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(len(jti)))
	preimage = append(preimage, jti...)

	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}
