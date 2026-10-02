// Package authz provides small, policy-neutral authorization primitives.
package authz

import (
	"errors"
	"fmt"
)

const (
	MaxKeyBytes   = 100
	MaxPermission = 256
)

// Permission is an application-owned, case-sensitive permission key.
// The framework assigns no meaning or inheritance to a key.
type Permission string

func Parse(value string) (Permission, error) {
	if len(value) == 0 || len(value) > MaxKeyBytes {
		return "", errors.New("permission length must be between 1 and 100 bytes")
	}
	segmentStart := true
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '.' {
			if segmentStart || i == len(value)-1 {
				return "", errors.New("permission contains an empty segment")
			}
			segmentStart = true
			continue
		}
		if segmentStart && (c < 'a' || c > 'z') {
			return "", errors.New("permission segments must start with a lowercase letter")
		}
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return "", errors.New("permission contains an unsupported character")
		}
		segmentStart = false
	}
	return Permission(value), nil
}

// Set stores an exact, bounded set. It deliberately has no wildcard,
// hierarchy, deny rule or implicit administrator behaviour.
type Set struct{ values map[Permission]struct{} }

func New(values ...string) (Set, error) {
	if len(values) > MaxPermission {
		return Set{}, fmt.Errorf("permission set exceeds %d entries", MaxPermission)
	}
	result := Set{values: make(map[Permission]struct{}, len(values))}
	for _, value := range values {
		permission, err := Parse(value)
		if err != nil {
			return Set{}, err
		}
		result.values[permission] = struct{}{}
	}
	return result, nil
}

func (s Set) Has(permission Permission) bool {
	_, ok := s.values[permission]
	return ok
}

func (s Set) HasAll(required ...Permission) bool {
	for _, permission := range required {
		if !s.Has(permission) {
			return false
		}
	}
	return true
}

func (s Set) HasAny(required ...Permission) bool {
	for _, permission := range required {
		if s.Has(permission) {
			return true
		}
	}
	return false
}

func (s Set) Len() int { return len(s.values) }
