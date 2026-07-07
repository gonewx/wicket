// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

type InputLengthRestrictions struct {
	ClientId                int
	ClientSecret            int
	Scope                   int
	RedirectUri             int
	Nonce                   int
	UiLocale                int
	LoginHint               int
	AcrValues               int
	GrantType               int
	UserName                int
	Password                int
	CspReport               int
	IdentityProvider        int
	ExternalError           int
	AuthorizationCode       int
	DeviceCode              int
	RefreshToken            int
	TokenHandle             int
	Jwt                     int
	CodeChallengeMinLength  int
	CodeChallengeMaxLength  int
	CodeVerifierMinLength   int
	CodeVerifierMaxLength   int
	ResourceGapMaxLength    int
	BindingMessage          int
	UserCode                int
	IdTokenHint             int
	LoginHintToken          int
	AuthenticationRequestId int
}

const (
	Default = 100
)

func NewInputLengthRestrictions() *InputLengthRestrictions {
	return &InputLengthRestrictions{
		ClientId:                Default,
		ClientSecret:            Default,
		Scope:                   300,
		RedirectUri:             400,
		Nonce:                   300,
		UiLocale:                Default,
		LoginHint:               Default,
		AcrValues:               300,
		GrantType:               Default,
		UserName:                Default,
		Password:                Default,
		CspReport:               2000,
		IdentityProvider:        Default,
		ExternalError:           Default,
		AuthorizationCode:       Default,
		DeviceCode:              Default,
		RefreshToken:            Default,
		TokenHandle:             Default,
		Jwt:                     51200,
		CodeChallengeMinLength:  43,
		CodeChallengeMaxLength:  128,
		CodeVerifierMinLength:   43,
		CodeVerifierMaxLength:   128,
		ResourceGapMaxLength:    512,
		BindingMessage:          Default,
		UserCode:                Default,
		IdTokenHint:             4000,
		LoginHintToken:          4000,
		AuthenticationRequestId: Default,
	}
}
