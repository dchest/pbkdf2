package pbkdf2

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

// Test vectors from http://tools.ietf.org/html/rfc6070
var testVectors = []struct {
	password string
	salt     string
	iter     int
	output   []byte
}{
	{
		"password",
		"salt",
		1,
		[]byte{0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6},
	},
	{
		"password",
		"salt",
		2,
		[]byte{0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57},
	},
	{
		"password",
		"salt",
		4096,
		[]byte{0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1},
	},
	//// Takes too long:
	//	{
	//		"password",
	//		"salt",
	//		16777216,
	//		[]byte{0xee,0xfe,0x3d,0x61,0xcd,0x4d,0xa4,0xe4,0xe9,0x94,0x5b,0x3d,0x6b,0xa2,0x15,0x8c,0x26,0x34,0xe9,0x84},
	//	},
	{
		"passwordPASSWORDpassword",
		"saltSALTsaltSALTsaltSALTsaltSALTsalt",
		4096,
		[]byte{0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38},
	},
	{
		"pass\000word",
		"sa\000lt",
		4096,
		[]byte{0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3},
	},
}


func TestWithHMAC(t *testing.T) {
	for i, v := range testVectors {
		o := WithHMAC(sha1.New, []byte(v.password), []byte(v.salt), v.iter, len(v.output))
		if !bytes.Equal(o, v.output) {
			t.Errorf("%d: expected %x, got %x", i, v.output, o)
		}
	}
}
