// Package repos handles persistence for the verification service: the
// CouchDB-backed (and in-memory, for tests) case store and the
// filesystem-backed identity loader. Following the house style, repos
// exposes concrete structs and leaves interface definitions to their
// consumers in the domain package.
package repos

import "errors"

// Errors returned by the persistence layer.
var (
	// ErrNotFound means no record exists for the requested key.
	ErrNotFound = errors.New("repos: record not found")
	// ErrConflict means the underlying store rejected the update
	// because the supplied _rev is stale. Callers should re-Get
	// the record and retry.
	ErrConflict = errors.New("repos: revision conflict")
)
