// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package contexts

// / Provides the context necessary to construct a logout notification.
type LogoutNotificationContext struct {
	///  The SubjectId of the user.
	SubjectId string

	/// The session Id of the user's authentication session.
	SessionId string

	/// The issuer for the back-channel logout
	Issuer string

	/// The list of client Ids that the user has authenticated to.
	ClientIds []string
}
