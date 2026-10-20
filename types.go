// types.go — общие константы и структура KDF-параметров.
package main

const (
	saltLen    = 16
	keyLen     = 32
	cipherName = "xchacha20-poly1305"

	defTime = uint32(3)
	defMem  = uint32(512)
	defPar  = uint32(2)
)

type kdfParams struct {
	Algorithm   string `json:"algorithm"`
	Salt        string `json:"salt"`
	Time        uint32 `json:"time"`
	MemoryMiB   uint32 `json:"memory_mib"`
	Parallelism uint32 `json:"parallelism"`
}
