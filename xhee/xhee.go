// Package xhee is the email half of the X-Vare account scheme.
//
// The client sends hex(sha256(lower(trim(email)) + Salt)) instead of an
// address. The server stores HMAC-SHA256 of that value under a secret, and
// looks accounts up by it. The address itself never reaches the server.
package xhee

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/x-vare/xhe/internal/clienthash"
)

// Salt is the public salt mixed into the client-side hash. It is not a
// secret: it only keeps the hash from being a bare SHA-256 of the address, and
// it has to be identical on every client.
const Salt = "xvare-xhee-public-salt-v1"

var (
	// ErrBadClientHash is returned when the client hash is not 64 hex characters.
	ErrBadClientHash = errors.New("xhee: client hash must be 64 hex characters")
	// ErrNoSecret is returned when the current server secret is empty.
	ErrNoSecret = errors.New("xhee: empty server secret")
)

// ClientHash is what the client sends: hex(sha256(lower(trim(email)) + Salt)).
func ClientHash(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email)) + Salt))
	return hex.EncodeToString(sum[:])
}

// Hasher turns client hashes into the values stored in the database. The first
// secret is current; the rest are older ones kept only so existing rows can
// still be found.
type Hasher struct {
	secrets [][]byte
}

// NewHasher returns a Hasher keyed with current. Secrets passed as old are used
// for lookups only, never for new rows.
func NewHasher(current string, old ...string) (*Hasher, error) {
	if current == "" {
		return nil, ErrNoSecret
	}
	h := &Hasher{secrets: [][]byte{[]byte(current)}}
	for _, s := range old {
		if s != "" && !h.has(s) {
			h.secrets = append(h.secrets, []byte(s))
		}
	}
	return h, nil
}

func (h *Hasher) has(s string) bool {
	for _, k := range h.secrets {
		if string(k) == s {
			return true
		}
	}
	return false
}

func mac(key []byte, clientHash string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(clientHash))
	return hex.EncodeToString(m.Sum(nil))
}

// Hash returns the value to store for clientHash, keyed with the current secret.
func (h *Hasher) Hash(clientHash string) (string, error) {
	if !clienthash.Valid(clientHash) {
		return "", ErrBadClientHash
	}
	return mac(h.secrets[0], strings.ToLower(clientHash)), nil
}

// Candidates returns every value clientHash could be stored as, current secret
// first. Use it for `WHERE email_hash IN (...)` while an old secret is still
// in rotation.
func (h *Hasher) Candidates(clientHash string) ([]string, error) {
	if !clienthash.Valid(clientHash) {
		return nil, ErrBadClientHash
	}
	c := strings.ToLower(clientHash)
	out := make([]string, 0, len(h.secrets))
	for _, k := range h.secrets {
		out = append(out, mac(k, c))
	}
	return out, nil
}

// Match reports whether stored is the hash of clientHash under any known
// secret. legacy is true when only an old secret matched, which is the signal
// to rewrite the row with Hash.
func (h *Hasher) Match(clientHash, stored string) (ok, legacy bool) {
	cands, err := h.Candidates(clientHash)
	if err != nil {
		return false, false
	}
	for i, c := range cands {
		if subtle.ConstantTimeCompare([]byte(c), []byte(stored)) == 1 {
			return true, i > 0
		}
	}
	return false, false
}
