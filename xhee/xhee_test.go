package xhee

import (
	"strings"
	"testing"
)

// Expected values were produced by the Node code that runs on x-vare.com
// (crypto), not by this package.
const (
	nodeEmail1  = "c0fcaf97556612e158cabcb03f4bed05473657128c0a0d1d4a8cfadc1f56bea1"
	nodeEmail2  = "dc1ccaadb889073a383114df5747d56c78677348abddc6a17bc0dbfde7e75059"
	nodeHMAC    = "262248309344bdb69223f0845125d0ff644a6a9255627326158ccd78d4c24b49"
	nodeHMACOld = "54202052726506893fccf63c7551f0d72f9b10f098e26146518fa70f5d68b5de"
)

func TestClientHash(t *testing.T) {
	cases := []struct{ in, want string }{
		{"User@Example.COM  ", nodeEmail1},
		{"user@example.com", nodeEmail1},
		{"почта@пример.рф", nodeEmail2},
	}
	for _, c := range cases {
		if got := ClientHash(c.in); got != c.want {
			t.Errorf("ClientHash(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestHasher(t *testing.T) {
	h, err := NewHasher("server-secret-A", "server-secret-OLD", "server-secret-A", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.Hash(nodeEmail1)
	if err != nil || got != nodeHMAC {
		t.Fatalf("Hash = %s, %v", got, err)
	}
	if up, _ := h.Hash(strings.ToUpper(nodeEmail1)); up != nodeHMAC {
		t.Error("hash depends on hex case")
	}
	c, _ := h.Candidates(nodeEmail1)
	if len(c) != 2 || c[0] != nodeHMAC || c[1] != nodeHMACOld {
		t.Fatalf("candidates: %v", c)
	}
	if ok, legacy := h.Match(nodeEmail1, nodeHMAC); !ok || legacy {
		t.Error("current secret")
	}
	if ok, legacy := h.Match(nodeEmail1, nodeHMACOld); !ok || !legacy {
		t.Error("old secret should match and report legacy")
	}
	if ok, _ := h.Match(nodeEmail2, nodeHMAC); ok {
		t.Error("different email matched")
	}
	if ok, _ := h.Match("zz", nodeHMAC); ok {
		t.Error("malformed client hash matched")
	}
	if _, err := h.Hash("short"); err != ErrBadClientHash {
		t.Errorf("err = %v", err)
	}
	if _, err := NewHasher(""); err != ErrNoSecret {
		t.Errorf("err = %v", err)
	}
}
