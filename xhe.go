// Package xhe documents the X-Vare account scheme; the code is in the
// subpackages, one per protocol:
//
//	xhee  email addresses  (client SHA-256, server HMAC)
//	xhpe  passwords        (client PBKDF2, server pepper + bcrypt)
//
// Both follow the same shape. The client hashes the value first, so the server
// never receives an email address or a password, and the server adds a keyed
// step of its own before writing to the database. Secrets can be rotated:
// the newest one is used for everything written from now on, older ones are
// still accepted until the rows are migrated.
//
// None of this replaces TLS or a rate limit on the login endpoint.
package xhe
