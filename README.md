# nkp

`nkp` stores a free-form secret file as one encrypted blob. Argon2id derives the key and
XChaCha20-Poly1305 seals the complete file. See [FORMAT.md](FORMAT.md) for the format and
recovery contract.

## Install

```sh
git clone https://github.com/s3nn1k/nkp.git ~/projects/nkp
make -C ~/projects/nkp install
```

`make install` builds the current platform from source and atomically installs
`~/.local/bin/nkp`. Go is the only build dependency.

## Configure

Set the directory that holds `<name>.nkpb` bases:

```sh
export NKP_VAULT="$HOME/.nkp-vault"
```

## Use

```sh
nkp init work
nkp unlock work
nkp lock work
nkp list work
nkp show work section
nkp info work
nkp rekey work
```

Plaintext exists only in `<name>.txt` between `unlock` and `lock`. `show` decrypts in
memory without creating a plaintext file. `--file <path>` addresses a pair outside
`$NKP_VAULT`.

## Recovery bundle

```sh
make -C ~/projects/nkp bundle
```

The bundle command reads encrypted bases and their recovery README from `$NKP_VAULT`,
cross-compiles static binaries into a temporary directory, and writes a self-contained
archive under `dist/`. Binaries and bases are never tracked by this repository.

## Development

```sh
make fmt
make lint
make test
make build
```
