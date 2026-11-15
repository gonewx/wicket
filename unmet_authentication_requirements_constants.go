// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket

import "errors"

// AuthorizeErrorsUnmetAuthenticationRequirements is the authorization error
// (OpenID Connect Core Error Code unmet_authentication_requirements 1.0, §1)
// returned when the provider cannot satisfy the authentication requirements
// the client requested, such as the acr_values it listed.
var AuthorizeErrorsUnmetAuthenticationRequirements = errors.New("unmet_authentication_requirements")
