// Package xhpe is the password half of the X-Vare account scheme.
//
// The client sends hex(PBKDF2-SHA256(password, device salt, Iterations)) instead
// of the password. The server never stores that value as is: it adds a pepper
// and runs bcrypt over the result, so a copy of the database is not enough to
// replay logins.
package xhpe

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/x-vare/xhe/internal/clienthash"
)

// Iterations is the work factor of the client-side step. It is part of
// the wire format: every client has to use the same number, so changing it
// means issuing new salts, not just editing a constant.
const Iterations = 100_000

var (
	// ErrBadClientHash is returned when the client hash is not 64 hex characters.
	ErrBadClientHash = errors.New("xhpe: client hash must be 64 hex characters")
	// ErrNoSecret is returned when the current pepper is empty.
	ErrNoSecret = errors.New("xhpe: empty server pepper")
)

// NewSalt returns a fresh 32-byte device salt as hex. It is generated once per
// account on the client and stored next to the hash; it is not a secret.
func NewSalt() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ClientHash derives the value the client sends instead of a password:
// hex(PBKDF2-HMAC-SHA256(utf8(password), salt, Iterations, 32)).
// saltHex is the device salt from NewSalt.
func ClientHash(password, saltHex string) (string, error) {
	return ClientHashN(password, saltHex, Iterations)
}

// ClientHashN is ClientHash with an explicit iteration count,
// for tests and for clients that negotiated a different work factor.
func ClientHashN(password, saltHex string, iterations int) (string, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) == 0 {
		return "", errors.New("xhpe: salt must be non-empty hex")
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// Scheme selects how the server combines the pepper with the client hash.
type Scheme int

const (
	// SchemeHMAC stores "xhpe2$" + bcrypt(base64(HMAC-SHA256(pepper, clientHash))).
	// The whole pepper and the whole client hash count. This is the default.
	SchemeHMAC Scheme = iota

	// SchemeConcat stores plain bcrypt(clientHash + pepper), the layout the
	// first X-Vare deployments used. bcrypt reads only the first 72 bytes, and
	// a client hash is already 64 of them, so only the first 8 bytes of the
	// pepper take part. Kept so existing rows can be verified and, if needed,
	// written; prefer SchemeHMAC for anything new.
	SchemeConcat
)

const hmacPrefix = "xhpe2$"

// Hasher is the server half of XHPE.
type Hasher struct {
	peppers [][]byte
	cost    int
	scheme  Scheme
}

// Option customises NewHasher.
type Option func(*Hasher)

// WithCost sets the bcrypt cost for new hashes (default 12).
func WithCost(cost int) Option { return func(h *Hasher) { h.cost = cost } }

// WithScheme picks the scheme used for new hashes (default SchemeHMAC).
// Verification accepts both regardless of this setting.
func WithScheme(s Scheme) Option { return func(h *Hasher) { h.scheme = s } }

// NewHasher returns a Hasher using current as the pepper for new
// hashes. Peppers listed in old are tried when verifying, so rotation does not
// lock anybody out.
func NewHasher(current string, old []string, opts ...Option) (*Hasher, error) {
	if current == "" {
		return nil, ErrNoSecret
	}
	h := &Hasher{peppers: [][]byte{[]byte(current)}, cost: 12}
	for _, p := range old {
		if p == "" {
			continue
		}
		dup := false
		for _, k := range h.peppers {
			dup = dup || string(k) == p
		}
		if !dup {
			h.peppers = append(h.peppers, []byte(p))
		}
	}
	for _, o := range opts {
		o(h)
	}
	if h.cost < bcrypt.MinCost || h.cost > bcrypt.MaxCost {
		return nil, bcrypt.InvalidCostError(h.cost)
	}
	return h, nil
}

func (h *Hasher) input(s Scheme, pepper []byte, clientHash string) []byte {
	switch s {
	case SchemeConcat:
		in := []byte(clientHash + string(pepper))
		if len(in) > 72 { // what bcrypt libraries in other languages do silently
			in = in[:72]
		}
		return in
	default:
		m := hmac.New(sha256.New, pepper)
		m.Write([]byte(clientHash))
		return []byte(base64.StdEncoding.EncodeToString(m.Sum(nil)))
	}
}

// Hash returns the string to store for clientHash.
func (h *Hasher) Hash(clientHash string) (string, error) {
	if !clienthash.Valid(clientHash) {
		return "", ErrBadClientHash
	}
	clientHash = strings.ToLower(clientHash)
	b, err := bcrypt.GenerateFromPassword(h.input(h.scheme, h.peppers[0], clientHash), h.cost)
	if err != nil {
		return "", err
	}
	if h.scheme == SchemeHMAC {
		return hmacPrefix + string(b), nil
	}
	return string(b), nil
}

// Result describes a successful or failed verification.
type Result struct {
	OK bool
	// NeedsRehash is set when the password is right but the stored value is
	// not what Hash would produce today: an older pepper, the other scheme, or
	// a lower bcrypt cost. Call Hash again and update the row.
	NeedsRehash bool
}

// Verify checks clientHash against a stored value produced by Hash, or by the
// original concatenating layout.
func (h *Hasher) Verify(clientHash, stored string) (Result, error) {
	if !clienthash.Valid(clientHash) {
		return Result{}, ErrBadClientHash
	}
	if stored == "" {
		return Result{}, nil
	}
	clientHash = strings.ToLower(clientHash)

	scheme, body := SchemeConcat, stored
	if strings.HasPrefix(stored, hmacPrefix) {
		scheme, body = SchemeHMAC, strings.TrimPrefix(stored, hmacPrefix)
	}
	// Try every pepper even after a hit would be possible: the cost of a
	// failed login should not reveal which pepper an account was written with.
	matched := -1
	for i, p := range h.peppers {
		if bcrypt.CompareHashAndPassword([]byte(body), h.input(scheme, p, clientHash)) == nil && matched < 0 {
			matched = i
		}
	}
	if matched < 0 {
		return Result{}, nil
	}
	cost, err := bcrypt.Cost([]byte(body))
	stale := err != nil || cost < h.cost || scheme != h.scheme || matched != 0
	return Result{OK: true, NeedsRehash: stale}, nil
}
