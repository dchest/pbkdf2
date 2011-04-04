package pbkdf2

import (
	"bytes"
	"crypto/sha1"
	"hash"
	"testing"
)

func tt(t *testing.T, p string, s string, h func()hash.Hash, i int, rl int, cres []byte) {
	pp := []byte(p)
	ss := []byte(s)
	res := WithHMAC(h, pp, ss, i, rl)
	if !bytes.Equal(cres, res) {
		t.Errorf("Invalid PBKDF2: expected %x, got %x", cres, res)
	}
}

func rt(h func()hash.Hash, t *testing.T) {
	tt(t, "foobar", "goo", h, 0, 0, []byte{})
	tt(t, "foobar", "goo", h, 0, 8, []byte{77, 143, 141, 64, 196, 163, 251, 183})
	tt(t, "foobar", "goo", h, 1, 8, []byte{77, 143, 141, 64, 196, 163, 251, 183})
	tt(t, "foobar", "goo", h, 0, 33, []byte{77, 143, 141, 64, 196, 163, 251, 183, 124, 86, 88, 214, 86, 145, 123, 6, 25, 119, 42, 183, 52, 232, 71, 60, 24, 220, 84, 176, 110, 220, 222, 25, 41})
	tt(t, "foobar", "goo", h, 1, 33, []byte{77, 143, 141, 64, 196, 163, 251, 183, 124, 86, 88, 214, 86, 145, 123, 6, 25, 119, 42, 183, 52, 232, 71, 60, 24, 220, 84, 176, 110, 220, 222, 25, 41})
	tt(t, "foobar", "goo", h, 99, 33, []byte{52, 231, 127, 102, 146, 5, 107, 205, 237, 136, 102, 199, 69, 221, 29, 209, 135, 238, 185, 250, 92, 114, 22, 73, 152, 233, 92, 190, 243, 86, 114, 207, 65})
}

func TestPbkdf2(t *testing.T) {
	rt(sha1.New, t)
}
