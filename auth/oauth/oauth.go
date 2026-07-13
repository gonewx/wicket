// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package oauth

const (
	/// code_verifier defined in https://tools.ietf.org/html/rfc7636
	CodeVerifierKey = "code_verifier"

	/// code_challenge defined in https://tools.ietf.org/html/rfc7636
	CodeChallengeKey = "code_challenge"

	/// code_challenge_method defined in https://tools.ietf.org/html/rfc7636
	CodeChallengeMethodKey = "code_challenge_method"

	/// S256 defined in https://tools.ietf.org/html/rfc7636
	CodeChallengeMethodS256 = "S256"
)
