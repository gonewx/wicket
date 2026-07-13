// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package google

import (
	"github.com/gonewx/wicket/auth/oauth"
)

type ChallengeProperties struct {
	*oauth.ChallengeProperties
}

func NewChallengeProperties() *ChallengeProperties {
	return &ChallengeProperties{
		ChallengeProperties: oauth.NewChallengeProperties(),
	}
}

func (cp *ChallengeProperties) AccessType() string {
	return cp.GetParameter(AccessTypeKey).(string)
}

func (cp *ChallengeProperties) SetAccessType(accessType string) {
	cp.SetParameter(AccessTypeKey, accessType)
}

func (cp *ChallengeProperties) ApprovalPrompt() string {
	return cp.GetParameter(ApprovalPromptKey).(string)
}

func (cp *ChallengeProperties) SetApprovalPrompt(approvalPrompt string) {
	cp.SetParameter(ApprovalPromptKey, approvalPrompt)
}

func (cp *ChallengeProperties) IncludeGrantedScopes() bool {
	return cp.GetParameter(IncludeGrantedScopesKey).(bool)
}

func (cp *ChallengeProperties) SetIncludeGrantedScopes(includeGrantedScopes bool) {
	cp.SetParameter(IncludeGrantedScopesKey, includeGrantedScopes)
}

func (cp *ChallengeProperties) LoginHint() string {
	return cp.GetParameter(LoginHintKey).(string)
}

func (cp *ChallengeProperties) SetLoginHint(loginHint string) {
	cp.SetParameter(LoginHintKey, loginHint)
}

func (cp *ChallengeProperties) Prompt() string {
	return cp.GetParameter(PromptParameterKey).(string)
}

func (cp *ChallengeProperties) SetPrompt(prompt string) {
	cp.SetParameter(PromptParameterKey, prompt)
}
