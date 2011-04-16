Package pbkdf2
==============

Package pbkdf2 implements PBKDF2 key derivation function.

(Slightly modified version of https://bitbucket.org/taruti/pbkdf2.go,
with password helper functions removed)


Functions
---------

### func WithHMAC

	func WithHMAC(hash func() hash.Hash, password []byte, salt []byte, iterations int, outlen int) []byte

WithHMAC derives key of length outlen from the provided password, salt,
and the number of iterations using PKCS#5 PBKDF2 with the provided
hash function in HMAC.

Caller is responsible to make sure that outlen < (2^32-1) * hash.Size().


Example
-------

	package main

	import (
		"fmt"
		"crypto/rand"
		"crypto/sha256"
		"github.com/dchest/pbkdf2"
	)


	func main() {
		password := "hello"
		// Get random salt
		salt := make([]byte, 32)
		if _, err := rand.Reader.Read(salt); err != nil {
			panic("random reader failed")
		}
		// Derive key
		key := pbkdf2.WithHMAC(sha256.New, password, salt, 9999, 64)
		fmt.Printf("%x", key)
	}

