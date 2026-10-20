// crypto.go — шифр/дешифр: Argon2id (KDF) + XChaCha20-Poly1305 (AEAD).
package main

import (
	"encoding/base64"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func b64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// zero wipes a secret buffer (best-effort; not a guarantee under a moving GC).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// deriveKey runs Argon2id over the password+salt with the stored parameters.
// Memory is stored as MiB but passed to Argon2 as KiB.
func deriveKey(pw, salt []byte, k kdfParams) []byte {
	return argon2.IDKey(pw, salt, k.Time, k.MemoryMiB*1024, byte(k.Parallelism), keyLen)
}

// open decrypts+verifies; returns error if key is wrong or data was tampered.
func open(key, nonce, ct, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ct, aad)
}
