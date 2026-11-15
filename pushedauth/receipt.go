// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauth

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/gonewx/wicket/dp"
)

// entryReceiptKind marks a protected value as an entry receipt. Receipts and
// pushed payloads share the pushed authorization protector; the marker keeps
// one from being taken for the other.
const entryReceiptKind = "pushed_authorization_entry_receipt"

// entryReceipt is the plain content of an entry receipt: it binds the store
// key of one request_uri to the instant the request entered the authorize
// endpoint.
type entryReceipt struct {
	Kind      string `json:"kind"`
	Key       string `json:"key"`
	EnteredAt int64  `json:"entered_at"`
}

// issueEntryReceipt returns the receipt of an entry of the request stored
// under key at enteredAt: the protected JSON content, unpadded base64url
// encoded.
func issueEntryReceipt(protector dp.DataProtector, key string, enteredAt time.Time) (string, error) {
	plain, err := json.Marshal(entryReceipt{Kind: entryReceiptKind, Key: key, EnteredAt: enteredAt.UnixNano()})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(protector.Protect(plain)), nil
}

// validEntryReceipt reports whether receipt is a receipt this server issued
// for the request stored under key, recording an entry no later than now and
// before entryExpiration.
func validEntryReceipt(protector dp.DataProtector, receipt string, key string, now time.Time, entryExpiration time.Time) bool {
	if receipt == "" {
		return false
	}
	protected, err := base64.RawURLEncoding.DecodeString(receipt)
	if err != nil {
		return false
	}
	plain, err := protector.Unprotect(protected)
	if err != nil {
		return false
	}
	var content entryReceipt
	if err := json.Unmarshal(plain, &content); err != nil {
		return false
	}
	if content.Kind != entryReceiptKind || content.Key != key {
		return false
	}
	enteredAt := time.Unix(0, content.EnteredAt)
	return !enteredAt.After(now) && enteredAt.Before(entryExpiration)
}
