package envelope

// Store persists Envelope records keyed on the server-absolute path
// of the ciphertext file. Implementations live in storage backends
// (storage/bolt).
//
// The interface is small on purpose: the EncryptingFS wrapper only
// needs Get/Put/Delete/Rename. There is no List — enumerating
// envelopes serves no real use case and would expose a size-of-fs
// metric operators don't need.
//
// All methods must be safe for concurrent use — EncryptingFS may
// be fanned out across many goroutines for concurrent uploads.
type Store interface {
	// Get returns the envelope for the given absolute path, or a
	// distinguishable "not found" error (implementations should
	// wrap fberrors.ErrNotExist). Missing envelopes are a data-
	// plane integrity event — a file on disk without a matching
	// envelope means either (a) unencrypted legacy file or (b)
	// deleted envelope with orphaned ciphertext; either way the
	// caller has to decide what to do.
	Get(absPath string) (*Envelope, error)

	// Put upserts the envelope. Called after a successful write of
	// the ciphertext to disk — if Put fails, the caller must delete
	// the ciphertext to avoid orphans.
	Put(absPath string, env *Envelope) error

	// Delete removes the envelope. Must be idempotent — deleting a
	// file that never had an envelope is a no-op, not an error.
	// Called alongside file Remove in the handler.
	Delete(absPath string) error

	// Rename moves an envelope from oldPath to newPath atomically.
	// Called by PATCH rename/move so the envelope follows the
	// ciphertext. Must roll back cleanly if the fs-layer move
	// subsequently fails (the typical ordering is: try envelope
	// rename first — if it fails, the fs op isn't attempted).
	Rename(oldPath, newPath string) error
}
