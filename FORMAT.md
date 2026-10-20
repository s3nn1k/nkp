# nkp blob format (v1)

A base is a pair of files in a directory (`$NKP_VAULT`): `<name>.nkpb` - the encrypted
blob (always present) - and `<name>.txt` - the flat file, present only while unlocked. One
master password; Argon2id derives the key, XChaCha20-Poly1305 seals the whole flat file as
a single AEAD body. `init`/`unlock`/`lock` never parse the body - it is sealed byte-exact;
only `list`/`show` split it into sections.

## Blob file `<name>.nkpb`

```
"NKPB1\n"                       magic (dispatch + `file(1)`)
<JSON header>\n                  one line, see below
<ct>                             XChaCha20-Poly1305 ciphertext of the flat bytes
```

Header (JSON, single line):

```json
{
  "kdf": {
    "algorithm": "argon2id",
    "salt": "...",
    "time": 3,
    "memory_mib": 512,
    "parallelism": 2
  },
  "cipher": "xchacha20-poly1305",
  "nonce": "...",
  "locked_at": "2026-09-09T18:00:00Z"
}
```

- `key = Argon2id(master, salt, time, memory_mib, parallelism)` - same derivation for
  every seal; each seal generates a **fresh salt and nonce** (equal plaintexts produce
  different ciphertexts, so re-anchored headers always differ);
- `ct = XChaCha20-Poly1305.Seal(key, nonce, file_bytes, aad = magic + header + "\n")`; the
  AAD binds the whole header - tampering with KDF params or the nonce breaks the tag;
- `locked_at` - RFC3339 UTC of the last seal (init/lock/rekey);
- unknown JSON fields are ignored (older blobs with `v`/`gen`/`sealed_at` still open; the
  next lock rewrites the header in the current shape).

## Flat (unlocked) file `<name>.txt`

Written by `unlock`/`init` with one generated header line prepended:

```
# nkp:v1 blob=<name.nkpb> anchor=<12 hex> body=<12 hex>
<original file bytes, untouched>
```

- `anchor` = first 6 bytes of `sha256(magic+header+"\n")` of the blob that was unlocked -
  at `lock` it is compared against the current blob (detects a blob that advanced via git
  pull on another machine);
- `body` = first 6 bytes of `sha256(body)` - lets `lock` skip re-sealing when nothing
  changed;
- the header line is consumed only when it fully parses **and** `blob=` matches the paired
  blob - otherwise it is ordinary content (legacy headers with an extra `gen=` field are
  recognized and their unknown field ignored).

## Sections (for `list`/`show` only)

A section starts with the exact literal `#----[` at column 0:

```
#----[ postgres/all ]
password:
  multi#line            <- any other '#' lines are content
  ## double hash
```

- title = rest of the marker line, trailing `]` optional, trimmed; body = everything until
  the next `^#----[` line or EOF (byte-exact, empty lines included);
- a body line that must start with the literal itself is written `\#----[...`; `show`
  strips the backslash in output only;
- a parse collision is loud, not silent: a stray marker shows up as a bogus title in
  `list`.

## Lock verifications

1. The entered master must open the **current** blob (wrong master/tamper -> refuse,
   nothing is touched).
2. `anchor` from the flat header must match the current blob header. On mismatch: if the
   current blob already contains exactly the flat body (self-advance - a crash between
   seal and wipe), the flat is simply removed; otherwise it is a race -> refuse without
   `-f` (the previous version stays in git history of the blob).
3. Unchanged body (`body` tag match) -> no re-seal.
4. An **empty** body is refused without `-f` (truncate accident).
5. `lock` reports the KDF params it re-sealed with - a silent downgrade (an old weak blob
   restored from git) becomes visible.

A missing/foreign flat header degrades checks 2-3 to a warning; check 1 never depends on
the header. `lock --all` continues past failed bases (summary + non-zero exit) so a typo
cannot leave plaintext behind.

## Hardening

- KDF params are validated on load (`time` 1..64, `memory_mib` 1..16384, `parallelism`
  1..64, `argon2id`, nonce length): crafted headers die cleanly instead of panicking
  inside Argon2id; `init`/`rekey` validate their flags.
- Symlinks are refused for flat files (reading one would seal foreign content, wiping
  would destroy the target); wipe unlinks a symlink without following it.
- Stale `.nkp-tmp-*` files (crash leftovers, may contain plaintext) are swept from the
  target directory on every command (older than 1 minute, so parallel runs are safe).
- Base names must not contain spaces or `=` (they break the flat header fields); the empty
  master is refused.

## Addressing

- positional `<name>` resolves to `$NKP_VAULT/<name>.nkpb` + `<name>.txt`; the directory
  is required for name addressing and is not scanned recursively;
- `--file <path>` addresses a raw `<stem>.txt`/`<stem>.nkpb` pair anywhere (no short form:
  `-f` is force);
- file-ish positional args (containing `/` or ending in `.txt`/`.nkpb`/`.nkp`) are refused
  with a hint to use `--file`.

## Reimplementation

Standardized primitives only: libsodium (`crypto_pwhash` +
`crypto_aead_xchacha20poly1305_ietf`, aad = magic+header+newline), Python `argon2-cffi` +
`pynacl`, Rust `argon2` + `chacha20poly1305`.

---

# Legacy: nkp entry format (v2)

Kept for reading old backups (e.g. a retired `vault.nkp` cold-backup). A JSON container
holds an encrypted **index** (titles) plus one separately-encrypted ciphertext per entry
password; the same Argon2id + XChaCha20-Poly1305 primitives.
`key = Argon2id(password, salt, t, mem, par)`; index
`ct = AEAD.Seal(key, nonce_i, tree_json, aad="index")`; entry
`ct = AEAD.Seal(key, nonce_e, password_bytes, aad=<entry id>)`. The current tool no longer
reads or writes this format.
