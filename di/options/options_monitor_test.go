// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

import (
	"fmt"
	"testing"
)

type testEntity struct {
	Value string
}

func (t *testEntity) New() *testEntity {
	return &testEntity{}
}

type testFactory struct {
	callCount int
	err       error
}

func (f *testFactory) Create(name string) (*testEntity, error) {
	f.callCount++
	if f.err != nil {
		return &testEntity{}, f.err
	}
	return &testEntity{Value: "created-" + name}, nil
}

func TestOptionsMonitorCurrentValue(t *testing.T) {
	t.Parallel()

	factory := &testFactory{}
	monitor := NewOptionsMonitor[*testEntity](factory)

	val, err := monitor.CurrentValue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.Value != "created-" {
		t.Fatalf("expected value %q, got %q", "created-", val.Value)
	}
}

func TestOptionsMonitorGetByName(t *testing.T) {
	t.Parallel()

	factory := &testFactory{}
	monitor := NewOptionsMonitor[*testEntity](factory)

	val, err := monitor.Get("custom")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.Value != "created-custom" {
		t.Fatalf("expected value %q, got %q", "created-custom", val.Value)
	}
}

func TestOptionsMonitorCachesResults(t *testing.T) {
	t.Parallel()

	factory := &testFactory{}
	monitor := NewOptionsMonitor[*testEntity](factory)

	v1, _ := monitor.Get("x")
	v2, _ := monitor.Get("x")

	if factory.callCount != 1 {
		t.Fatalf("expected factory called once, got %d", factory.callCount)
	}
	if v1 != v2 {
		t.Fatal("expected same pointer from cache")
	}
}

func TestOptionsMonitorEmptyNameFallsBackToDefault(t *testing.T) {
	t.Parallel()

	factory := &testFactory{}
	monitor := NewOptionsMonitor[*testEntity](factory)

	v1, _ := monitor.CurrentValue()
	v2, _ := monitor.Get("")

	if factory.callCount != 1 {
		t.Fatalf("expected factory called once for empty name, got %d", factory.callCount)
	}
	if v1 != v2 {
		t.Fatal("expected same pointer for empty name and CurrentValue")
	}
}

func TestOptionsMonitorPropagatesFactoryError(t *testing.T) {
	t.Parallel()

	factory := &testFactory{err: fmt.Errorf("factory failed")}
	monitor := NewOptionsMonitor[*testEntity](factory)

	_, err := monitor.Get("failing")
	if err == nil {
		t.Fatal("expected error from factory")
	}
	if err.Error() != "factory failed" {
		t.Fatalf("expected %q, got %q", "factory failed", err.Error())
	}
}

func TestOptionsMonitorDistinctNamesCreateDistinctEntries(t *testing.T) {
	t.Parallel()

	factory := &testFactory{}
	monitor := NewOptionsMonitor[*testEntity](factory)

	v1, _ := monitor.Get("a")
	v2, _ := monitor.Get("b")

	if factory.callCount != 2 {
		t.Fatalf("expected factory called twice, got %d", factory.callCount)
	}
	if v1 == v2 {
		t.Fatal("expected different pointers for distinct names")
	}
	if v1.Value != "created-a" || v2.Value != "created-b" {
		t.Fatalf("unexpected values: a=%q, b=%q", v1.Value, v2.Value)
	}
}
