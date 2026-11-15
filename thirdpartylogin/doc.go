// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package thirdpartylogin lets a host initiate a client's login from a third
// party, as OpenID Connect Core 1.0 section 4 describes: the browser is sent
// to the client's registered login initiation endpoint
// (ClientThirdPartyLoginMetadata.InitiateLoginUri) with the iss parameter
// naming this server, and the client then sends an authentication request
// back to it.
//
// BuildInitiationUrl is the pure construction of that URL. Initiate runs
// inside a host request that wicket's request scope wraps: it loads the
// enabled client through the validating client store, takes the issuer from
// the current request and answers with a 302 redirect. Only the GET form is
// produced; the client remains responsible for validating target_link_uri
// before it redirects to it.
//
// The login_hint value may identify a person (an e-mail address or a phone
// number). This package writes it to no log and to no error text.
package thirdpartylogin
