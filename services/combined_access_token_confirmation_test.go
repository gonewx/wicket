// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

type fixedConfirmation struct {
	value string
	err   error
}

func (f fixedConfirmation) Confirmation(context.Context, *http.Request, string) (string, error) {
	return f.value, f.err
}

func TestCombineAccessTokenConfirmationsWithNil(t *testing.T) {
	t.Parallel()
	only := fixedConfirmation{value: `{"jkt":"a"}`}
	if CombineAccessTokenConfirmations(nil, nil) != nil {
		t.Fatal("two nil sides combine to a value")
	}
	if got := CombineAccessTokenConfirmations(only, nil); got != AccessTokenConfirmation(only) {
		t.Fatalf("first only: %#v", got)
	}
	if got := CombineAccessTokenConfirmations(nil, only); got != AccessTokenConfirmation(only) {
		t.Fatalf("second only: %#v", got)
	}
}

func TestCombinedAccessTokenConfirmation(t *testing.T) {
	t.Parallel()
	failure := errors.New("refused")
	cases := map[string]struct {
		first, second fixedConfirmation
		want          map[string]any
		verbatim      string
		fails         bool
	}{
		"both empty":         {verbatim: ""},
		"first only":         {first: fixedConfirmation{value: `{"x5t#S256":"c"}`}, verbatim: `{"x5t#S256":"c"}`},
		"second only":        {second: fixedConfirmation{value: `{"jkt":"k"}`}, verbatim: `{"jkt":"k"}`},
		"merged":             {first: fixedConfirmation{value: `{"x5t#S256":"c"}`}, second: fixedConfirmation{value: `{"jkt":"k"}`}, want: map[string]any{"x5t#S256": "c", "jkt": "k"}},
		"member conflict":    {first: fixedConfirmation{value: `{"jkt":"a"}`}, second: fixedConfirmation{value: `{"jkt":"b"}`}, fails: true},
		"first not object":   {first: fixedConfirmation{value: `["a"]`}, second: fixedConfirmation{value: `{"jkt":"k"}`}, fails: true},
		"second not object":  {first: fixedConfirmation{value: `{"x5t#S256":"c"}`}, second: fixedConfirmation{value: `"k"`}, fails: true},
		"first fails":        {first: fixedConfirmation{err: failure}, second: fixedConfirmation{value: `{"jkt":"k"}`}, fails: true},
		"second fails":       {first: fixedConfirmation{value: `{"x5t#S256":"c"}`}, second: fixedConfirmation{err: failure}, fails: true},
		"second fails empty": {second: fixedConfirmation{err: failure}, fails: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			combined := CombineAccessTokenConfirmations(tc.first, tc.second)
			got, err := combined.Confirmation(context.Background(), nil, "client")
			if tc.fails {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				if (tc.first.err != nil || tc.second.err != nil) && !errors.Is(err, failure) {
					t.Fatalf("err = %v, want the side's own error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == nil {
				if got != tc.verbatim {
					t.Fatalf("got %q, want %q", got, tc.verbatim)
				}
				return
			}
			var members map[string]any
			if err := json.Unmarshal([]byte(got), &members); err != nil || !reflect.DeepEqual(members, tc.want) {
				t.Fatalf("got %s (%v), want %v", got, err, tc.want)
			}
		})
	}
}
