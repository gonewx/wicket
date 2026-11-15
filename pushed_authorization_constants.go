// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket

// Routes of the pushed authorization request endpoint (RFC 9126).
var (
	// ProtocolRoutePathsPushedAuthorization is the route of the pushed
	// authorization request endpoint.
	ProtocolRoutePathsPushedAuthorization = ProtocolRoutePathsConnectPathPrefix + "/pushedauthorization"
	// ProtocolRoutePathsMtlsPushedAuthorization is its mutual TLS alias
	// route.
	ProtocolRoutePathsMtlsPushedAuthorization = ProtocolRoutePathsMtlsPathPrefix + "/pushedauthorization"
)

// Pushed authorization requests (RFC 9126).
const (
	// EndpointNamesPushedAuthorizationRequest names the pushed authorization
	// request endpoint.
	EndpointNamesPushedAuthorizationRequest = "PushedAuthorizationRequest"

	// DiscoveryPushedAuthorizationRequestEndpoint is the discovery metadata
	// name of the endpoint URL (RFC 9126 section 5).
	DiscoveryPushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
	// DiscoveryRequirePushedAuthorizationRequests is the discovery metadata
	// name that says every client has to use pushed authorization requests
	// (RFC 9126 section 5).
	DiscoveryRequirePushedAuthorizationRequests = "require_pushed_authorization_requests"

	// AuthorizeRequestPushedEntryReceipt is the parameter carrying the entry
	// receipt of a pushed authorization request across the interaction
	// round trip. It is written by the server, never by a client.
	AuthorizeRequestPushedEntryReceipt = "par_entry_receipt"
)
