// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

type OptionsMonitor[T Entity[T]] interface {
	CurrentValue() (T, error)
	Get(name string) (T, error)
}

type optionsMonitor[T Entity[T]] struct {
	factory OptionsFactory[T]
	cache   map[string]T
}

func NewOptionsMonitor[T Entity[T]](factory OptionsFactory[T]) OptionsMonitor[T] {
	return &optionsMonitor[T]{
		factory: factory,
		cache:   make(map[string]T),
	}
}

func (m *optionsMonitor[T]) CurrentValue() (T, error) {
	return m.Get(DefaultName)
}

func (m *optionsMonitor[T]) Get(name string) (T, error) {
	if name == "" {
		name = DefaultName
	}
	if cached, ok := m.cache[name]; ok {
		return cached, nil
	}
	val, err := m.factory.Create(name)
	if err != nil {
		return val, err
	}
	m.cache[name] = val
	return val, nil
}
