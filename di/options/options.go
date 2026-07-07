// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

import "fmt"

const (
	DefaultName                     = ""
	DefaultValidationFailureMessage = "options validation failed"
)

type Entity[T any] interface {
	New() T
}

// ConfigureOptions applies name-independent configuration to an options value.
// input: options value -> behavior: mutate or reject it -> output: error.
type ConfigureOptions[T Entity[T]] interface {
	Configure(T) error
}

// PostConfigureOptions applies name-aware final configuration after setup.
// input: option name and value -> behavior: mutate or reject it -> output: error.
type PostConfigureOptions[T Entity[T]] interface {
	PostConfigure(string, T) error
}

// ValidateOptions checks a named options value after all configuration runs.
// input: option name and value -> behavior: validate -> output: error.
type ValidateOptions[T Entity[T]] interface {
	Validate(string, T) error
}

type Options[T Entity[T]] interface {
	Value() (T, error)
}

type OptionsFactory[T Entity[T]] interface {
	Create(string) (T, error)
}

type UnnamedOptionsManager[T Entity[T]] struct {
	factory OptionsFactory[T]
}

func NewUnnamedOptionsManager[T Entity[T]](factory OptionsFactory[T]) *UnnamedOptionsManager[T] {
	return &UnnamedOptionsManager[T]{factory: factory}
}

func (m *UnnamedOptionsManager[T]) Value() (T, error) {
	return m.factory.Create(DefaultName)
}

type optionsFactory[T Entity[T]] struct {
	configures     []ConfigureOptions[T]
	postConfigures []PostConfigureOptions[T]
	validates      []ValidateOptions[T]
}

func NewOptionsFactory[T Entity[T]](
	configures []ConfigureOptions[T],
	postConfigures []PostConfigureOptions[T],
	validates []ValidateOptions[T],
) OptionsFactory[T] {
	return &optionsFactory[T]{
		configures:     configures,
		postConfigures: postConfigures,
		validates:      validates,
	}
}

func (f *optionsFactory[T]) Create(name string) (T, error) {
	var zero T
	value := zero.New()
	for _, configure := range f.configures {
		if named, ok := configure.(interface {
			ConfigureWithName(string, T) error
		}); ok {
			if err := named.ConfigureWithName(name, value); err != nil {
				return value, err
			}
			continue
		}
		if err := configure.Configure(value); err != nil {
			return value, err
		}
	}
	for _, configure := range f.postConfigures {
		if err := configure.PostConfigure(name, value); err != nil {
			return value, err
		}
	}
	for _, validate := range f.validates {
		if err := validate.Validate(name, value); err != nil {
			return value, err
		}
	}
	return value, nil
}

type configureNameOptions[T Entity[T]] struct {
	name      string
	configure func(T) error
}

func NewConfigureNameOptions[T Entity[T]](name string, configure func(T) error) ConfigureOptions[T] {
	return &configureNameOptions[T]{name: name, configure: configure}
}

func (o *configureNameOptions[T]) Configure(value T) error {
	return o.ConfigureWithName(DefaultName, value)
}

func (o *configureNameOptions[T]) ConfigureWithName(name string, value T) error {
	if o.name != name {
		return nil
	}
	return o.configure(value)
}

type validateOptions[T Entity[T]] struct {
	name    string
	check   func(T) error
	message string
}

func NewValidateOptions[T Entity[T]](name string, check func(T) error, message string) ValidateOptions[T] {
	return &validateOptions[T]{name: name, check: check, message: message}
}

func (o *validateOptions[T]) Validate(name string, value T) error {
	if o.name != name {
		return nil
	}
	if err := o.check(value); err != nil {
		if o.message == "" {
			return err
		}
		return fmt.Errorf("%s: %w", o.message, err)
	}
	return nil
}
