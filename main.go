// nkp (NeoKeePass): encrypted secret blobs.
//
// One master password (Argon2id) seals a whole flat file as a single
// XChaCha20-Poly1305 body; a base is a pair <name>.nkpb + <name>.txt in
// $NKP_VAULT, edited through init/unlock → edit → lock. See FORMAT.md.
//
// Source layout (one package, split by concern):
//
//	types.go      constants + KDF params
//	crypto.go     Argon2id + AEAD primitives
//	input.go      password/line input
//	sections.go   '#----[' section parsing
//	blob.go       blob format + all commands
//	main.go       entry point + dispatch (this file)
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "info":
		cmdInfo(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "show":
		cmdShow(os.Args[2:])
	case "unlock":
		cmdUnlock(os.Args[2:])
	case "lock":
		cmdLock(os.Args[2:])
	case "rekey":
		cmdRekey(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `nkp — NeoKeePass: encrypted secret blobs (one master, Argon2id + XChaCha20-Poly1305).

A base is a pair of files in $NKP_VAULT: <name>.nkpb (encrypted blob, always)
and <name>.txt (flat, exists only while unlocked). Sections inside start with
'#----[ title ]' at column 0; everything else is content, sealed byte-exact.

usage:
  nkp init   [-t N -m MiB -p N] [-s] <name>              create the pair in $NKP_VAULT
                                                          (an existing <name>.txt is adopted)
  nkp unlock [-f] <name>                                 decrypt to <name>.txt (+ header line)
  nkp lock   [-f] <name> | --all                         verify master & re-seal, wipe flat
  nkp rekey  [-t N -m MiB -p N] [-s] <name>              change master / KDF params (content intact)
  nkp list   <name>                                      section titles (flat: no master; blob: master)
  nkp show   <name> [<section>]                          section body or whole file (one-shot)
  nkp info   <name>                                      KDF / locked_at / state (no master)

every command also accepts --file <path> instead of <name> for a raw
<stem>.txt / <stem>.nkpb pair outside $NKP_VAULT.

$NKP_VAULT - directory holding the bases; required for <name> addressing,
not scanned recursively (e.g. export NKP_VAULT="$HOME/.nkp-vault").
`)
}
