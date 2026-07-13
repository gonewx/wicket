// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package oauth

import "github.com/gonewx/wicket/auth"

const (
	ScopeKey = "scope"
)

type ChallengeProperties struct {
	*auth.Properties
}

func NewChallengeProperties() *ChallengeProperties {
	return &ChallengeProperties{
		Properties: auth.NewProperties(),
	}
}

func (cp *ChallengeProperties) Scope() []string {
	return cp.GetParameter(ScopeKey).([]string)
}

func (cp *ChallengeProperties) SetScope(scopes []string) {
	cp.SetParameter(ScopeKey, scopes)
}
