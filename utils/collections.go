// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package utils

import (
	"sort"
	"strings"
)

type EqualityComparer[T any] interface {
	Equal(T, T) bool
}

func Where[T any](items []T, predicate func(T) bool) []T {
	out := make([]T, 0)
	for _, item := range items {
		if predicate(item) {
			out = append(out, item)
		}
	}
	return out
}

func Select[T any, R any](items []T, selector func(T) R) []R {
	out := make([]R, 0, len(items))
	for _, item := range items {
		out = append(out, selector(item))
	}
	return out
}

func SelectMany[T any, R any](items []T, selector func(T) []R) []R {
	out := make([]R, 0)
	for _, item := range items {
		out = append(out, selector(item)...)
	}
	return out
}

func Contains[T comparable](items []T, value T) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func ContainsEq[T any](items []T, value T, comparer EqualityComparer[T]) bool {
	for _, item := range items {
		if comparer.Equal(item, value) {
			return true
		}
	}
	return false
}

func Any[T any](items []T) bool {
	return len(items) > 0
}

func AnyPred[T any](items []T, predicate func(T) bool) bool {
	for _, item := range items {
		if predicate(item) {
			return true
		}
	}
	return false
}

func All[T any](items []T, predicate func(T) bool) bool {
	for _, item := range items {
		if !predicate(item) {
			return false
		}
	}
	return true
}

func Distinct[T comparable](items []T) []T {
	seen := make(map[T]struct{}, len(items))
	out := make([]T, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func DistinctEq[T any](items []T, comparer EqualityComparer[T]) []T {
	out := make([]T, 0, len(items))
	for _, item := range items {
		if !ContainsEq(out, item, comparer) {
			out = append(out, item)
		}
	}
	return out
}

func Except[T comparable](items []T, exclusions []T) []T {
	out := make([]T, 0, len(items))
	for _, item := range items {
		if !Contains(exclusions, item) {
			out = append(out, item)
		}
	}
	return out
}

func IntersectLists[T comparable](lists [][]T) []T {
	if len(lists) == 0 {
		return nil
	}
	out := append([]T(nil), lists[0]...)
	for _, list := range lists[1:] {
		out = Where(out, func(item T) bool {
			return Contains(list, item)
		})
	}
	return Distinct(out)
}

func First[T any](items []T) T {
	if len(items) == 0 {
		var zero T
		return zero
	}
	return items[0]
}

func FirstPred[T any](items []T, predicate func(T) bool) T {
	return First(Where(items, predicate))
}

func FirstOrDefault[T any](items []T) T {
	return First(items)
}

func FirstOrDefaultPred[T any](items []T, predicate func(T) bool) T {
	return First(Where(items, predicate))
}

func SingleOrDefault[T any](items []T) T {
	if len(items) == 1 {
		return items[0]
	}
	var zero T
	return zero
}

func SingleOrDefaultPred[T any](items []T, predicate func(T) bool) T {
	return SingleOrDefault(Where(items, predicate))
}

func Skip[T any](items []T, count int) []T {
	if count >= len(items) {
		return nil
	}
	if count <= 0 {
		return items
	}
	return items[count:]
}

func SkipWhile[T any](items []T, predicate func(T) bool) []T {
	for i, item := range items {
		if !predicate(item) {
			return items[i:]
		}
	}
	return nil
}

func OrderByKeyDescMust[T any, K ~int | ~int64 | ~string](items []T, key func(T) K) []T {
	out := append([]T(nil), items...)
	sort.Slice(out, func(i, j int) bool { return key(out[i]) > key(out[j]) })
	return out
}

func Aggregate[T any](items []T, fn func(T, T) T) T {
	if len(items) == 0 {
		var zero T
		return zero
	}
	result := items[0]
	for _, item := range items[1:] {
		result = fn(result, item)
	}
	return result
}

func ToSpaceSeparatedString(items []string) string {
	return strings.Join(items, " ")
}
