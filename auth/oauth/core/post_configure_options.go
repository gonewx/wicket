// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"net/http"

	authcore "github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/auth/oauth"
	"github.com/gonewx/wicket/dp"
	optspkg "github.com/gonewx/wicket/di/options"
)

var _ optspkg.PostConfigureOptions[*Options] = (*PostConfigureOptions[*Options])(nil)

type PostConfigureOptions[T oauth.Options[T]] struct {
	dp dp.DataProtectionProvider
}

func NewPostConfigureOptions[T oauth.Options[T]](dataProtection dp.DataProtectionProvider) *PostConfigureOptions[T] {
	return &PostConfigureOptions[T]{
		dp: dataProtection,
	}
}

func (o *PostConfigureOptions[T]) PostConfigure(name string, options T) error {
	if options.DataProtectionProvider() == nil {
		options.SetDataProtectionProvider(o.dp)
	}

	if options.Backchannel() == nil {
		c := http.DefaultClient
		if options.BackchannelHttpHandler() != nil {
			c.Transport = options.BackchannelHttpHandler()
		}
		c.Timeout = options.BackchannelTimeout()
		options.SetBackchannel(c)
	}
	if options.StateDataFormat() == nil {
		dataProtector := options.DataProtectionProvider().Create("wicket.Authentication.OAuth" + name + "v1")
		options.SetStateDataFormat(authcore.NewPropertiesDataFormat(dataProtector))
	}

	return nil
}
