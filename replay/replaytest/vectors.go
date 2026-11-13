// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replaytest

import "github.com/gonewx/wicket/replay"

// KeyVector is one test vector for replay.Key: the three inputs and the key
// they must produce.
type KeyVector struct {
	Name      string
	Purpose   replay.Purpose
	Qualifier string
	JTI       string
	Key       string
}

// KeyVectors returns the test vectors for replay.Key in a new slice. The
// expected keys are literals computed outside Go, with sha256sum over the
// encoded bytes, so they do not depend on the function they check.
//
// V1 and V2 differ only in purpose. V3 and V4 concatenate to the same bytes
// without the length prefixes. V5 has a two-byte character in the qualifier,
// which counts as two. V6 has the shape of a DPoP proof: a key thumbprint and
// a URN jti.
func KeyVectors() []KeyVector {
	return []KeyVector{
		{
			Name:      "V1",
			Purpose:   replay.PurposeClientAssertion(),
			Qualifier: "client-a",
			JTI:       "jti-1",
			Key:       "d20bdf573a5e70c94195ad2ca9cd1a3920089024cc8e4d02c7d22469e639d59c",
		},
		{
			Name:      "V2",
			Purpose:   replay.PurposeDPoPProof(),
			Qualifier: "client-a",
			JTI:       "jti-1",
			Key:       "9a0f29a409a2502e8c859ac4626255105bad35ad5a0f080425af3c302783f647",
		},
		{
			Name:      "V3",
			Purpose:   replay.PurposeClientAssertion(),
			Qualifier: "ab",
			JTI:       "c",
			Key:       "1ed0f1c6edc07cefa06a7be4ca57ab1536abac237d63d3af0800d80176a0d6b8",
		},
		{
			Name:      "V4",
			Purpose:   replay.PurposeClientAssertion(),
			Qualifier: "a",
			JTI:       "bc",
			Key:       "872c8ac37fcd66cc458d779d9a111975d2b09287e684d7fd8e93f073094d1e11",
		},
		{
			Name:      "V5",
			Purpose:   replay.PurposeClientAssertion(),
			Qualifier: "client-\xc3\xbc",
			JTI:       "j:1",
			Key:       "cde74861978b6641dd1cb93a6d6512afc2d8dcede45cee7a821e31e4f3086e63",
		},
		{
			Name:      "V6",
			Purpose:   replay.PurposeDPoPProof(),
			Qualifier: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
			JTI:       "urn:uuid:7f9c",
			Key:       "0a4793514dc061e98e1750188ed9bfeedd571306bbe3fc19a75381c65883dadc",
		},
	}
}
