// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package messages

import "github.com/tidwall/gjson"

type ProtocolResponse struct {
	Raw string
}

func NewProtocolResponse() *ProtocolResponse {
	return &ProtocolResponse{}
}

func (r *ProtocolResponse) IsError() bool {
	return gjson.Get(r.Raw, "error").String() != ""
}
