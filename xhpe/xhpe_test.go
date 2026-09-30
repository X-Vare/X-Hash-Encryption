package xhpe

import (
	"strings"
	"testing"
)

// Expected values were produced by the Node code that runs on x-vare.com
// (crypto.pbkdf2Sync, bcryptjs), not by this package.
const (
	nodeSalt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	nodePW1  = "ef8970894e11c302383e9d31b220979179c2e8964100f3a99a52cdc7ce6f9f77"
	nodePW2  = "371e90d9c2ccad629774cddc0a3e357fe7e668bab8e6f20036fc6d6420a6f257"

	nodePepper        = "pepper-A-0123456789"
	nodeConcat        = "$2a$10$eLxxAiajSIF9gy.feg10vu0cKDYuiPp4qqCPhOjMsrq2si1dOw.QW"
	nodeConcatOldPepp = "$2a$10$vNAPEQ0xJ1IHN4IEtip2VuHiaw2JYg1c7hHdZxobPMWgSgB28R4NO"
	nodeOldPepper     = "pepper-OLD-9876543210"
)

func TestClientHash(t *testing.T) {
	for _, c := range []struct{ pw, want string }{
		{"correct horse battery staple", nodePW1},
		{"пароль №1", nodePW2},
	} {
		got, err := ClientHash(c.pw, nodeSalt)
		if err != nil || got != c.want {
			t.Errorf("ClientHash(%q) = %s, %v; want %s", c.pw, got, err, c.want)
		}
	}
	if _, err := ClientHash("x", "not hex"); err == nil {
		t.Error("bad salt accepted")
	}
	if _, err := ClientHash("x", ""); err == nil {
		t.Error("empty salt accepted")
	}
}

func TestNewSalt(t *testing.T) {
	a, _ := NewSalt()
	b, _ := NewSalt()
	if len(a) != 64 || a == b {
		t.Fatalf("salts: %q %q", a, b)
	}
}

func TestRoundTrip(t *testing.T) {
	h, err := NewHasher("pepper-1", nil, WithCost(4))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := h.Hash(nodePW1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "xhpe2$$2") {
		t.Fatalf("unexpected format: %s", stored)
	}
	if r, _ := h.Verify(nodePW1, stored); !r.OK || r.NeedsRehash {
		t.Errorf("right password: %+v", r)
	}
	if r, _ := h.Verify(nodePW2, stored); r.OK {
		t.Error("wrong password accepted")
	}
	if r, _ := h.Verify(nodePW1, ""); r.OK {
		t.Error("empty stored value accepted")
	}
	if _, err := h.Verify("nope", stored); err != ErrBadClientHash {
		t.Errorf("err = %v", err)
	}
}

func TestHMACSchemeUsesWholePepper(t *testing.T) {
	a, _ := NewHasher("pepper-A-0123456789", nil, WithCost(4))
	b, _ := NewHasher("pepper-A-DIFFERENT-TAIL", nil, WithCost(4))
	stored, _ := a.Hash(nodePW1)
	if r, _ := b.Verify(nodePW1, stored); r.OK {
		t.Error("peppers sharing an 8-byte prefix must not be interchangeable in the HMAC scheme")
	}
}

func TestConcatSchemeMatchesNode(t *testing.T) {
	h, _ := NewHasher(nodePepper, []string{nodeOldPepper}, WithCost(10), WithScheme(SchemeConcat))
	if r, _ := h.Verify(nodePW1, nodeConcat); !r.OK || r.NeedsRehash {
		t.Errorf("bcryptjs hash, current pepper: %+v", r)
	}
	if r, _ := h.Verify(nodePW1, nodeConcatOldPepp); !r.OK || !r.NeedsRehash {
		t.Errorf("bcryptjs hash, old pepper: %+v", r)
	}
	if r, _ := h.Verify(nodePW2, nodeConcat); r.OK {
		t.Error("wrong password accepted")
	}
	// Documented limitation: bcrypt only sees 72 bytes, 64 of them are the
	// client hash, so everything after the 8th byte of the pepper is ignored.
	tail, _ := NewHasher("pepper-A-DIFFERENT-TAIL", nil, WithCost(10), WithScheme(SchemeConcat))
	if r, _ := tail.Verify(nodePW1, nodeConcat); !r.OK {
		t.Error("expected the 72-byte truncation behaviour of the original scheme")
	}
}

func TestMigrationFromConcatToHMAC(t *testing.T) {
	h, _ := NewHasher(nodePepper, []string{nodeOldPepper}, WithCost(4)) // default: HMAC
	r, err := h.Verify(nodePW1, nodeConcat)
	if err != nil || !r.OK || !r.NeedsRehash {
		t.Fatalf("old row should verify and ask for a rehash: %+v %v", r, err)
	}
	fresh, _ := h.Hash(nodePW1)
	if r, _ := h.Verify(nodePW1, fresh); !r.OK || r.NeedsRehash {
		t.Errorf("after rehash: %+v", r)
	}
}

func TestCostChangeAsksForRehash(t *testing.T) {
	low, _ := NewHasher("p", nil, WithCost(4))
	high, _ := NewHasher("p", nil, WithCost(5))
	stored, _ := low.Hash(nodePW1)
	if r, _ := high.Verify(nodePW1, stored); !r.OK || !r.NeedsRehash {
		t.Errorf("%+v", r)
	}
}

func TestConstructorErrors(t *testing.T) {
	if _, err := NewHasher("", nil); err != ErrNoSecret {
		t.Errorf("err = %v", err)
	}
	if _, err := NewHasher("p", nil, WithCost(99)); err == nil {
		t.Error("cost 99 accepted")
	}
}
