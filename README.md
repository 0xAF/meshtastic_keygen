# Meshtastic Key Generator

A multi-threaded X25519 private key generator/search tool targeting Base64 prefixes/suffixes. Uses OpenSSL for keygen and Base64, and reports throughput once per second.

## Implementations

- C version: see `C/` (build and usage: `C/README.md`)
- Rust version: see `rust/` (build and usage: `rust/README.md`)

## Features

- Generates raw X25519 private keys and Base64-encodes them
- Matches when the Base64 string starts with a prefix or ends with the prefix plus '='
- Multi-threaded (user configurable)
- Periodic stats (1s): total keys and keys/sec in human-readable units

## Build

There are two implementations:

- C version in `C/` (depends on OpenSSL and pthreads)
- Rust version in `Rust/` (pure Rust)

Top-level convenience targets build the C version:

```sh
make            # builds C/meshtastic_keygen
make debug      # builds C/meshtastic_keygen_debug with -g -O0
```

Or build directly in subfolders.

### Rust version (Rust/)

A highly optimized Rust implementation is available under `Rust/`.

Build and run (release mode recommended):

```sh
cd Rust
cargo build --release
cargo run --release -- -s 0xAF -t 8 -c 2
```

Key differences vs C version:

- Uses Rust’s SmallRng and zero-allocation Base64 encoding into a fixed buffer
- Lock-free atomics for counters, clean shutdown via Ctrl-C
- Similar CLI: `-s/--search`, `-t/--threads`, `-c/--count`

## Usage (C version)

```sh
./meshtastic_keygen --search STR [--threads N] [--count C]
# or
./meshtastic_keygen -s STR [-t N] [-c C]
```

- `--search`, `-s` (required): Prefix string to search for in Base64.
  - Must contain only Base64 characters: A–Z, a–z, 0–9, +, /
  - Do not include '='; the tool will also match the suffix `STR=` automatically.
  - A match is printed if the Base64 starts with `STR` or ends with `STR=`.
- `--threads`, `-t` (optional): Number of worker threads. Default: 4.
- `--count`, `-c` (optional): Stop after finding C matching keys. Default: 1.

### Examples

```sh
# Search for Base64 values that start with 0xAF or end with 0xAF=
./meshtastic_keygen -s 0xAF -t 12

# Minimal: default 4 threads
./meshtastic_keygen -s hello

# Stop after 5 matching keys
./meshtastic_keygen -s 0xAF -c 5
```

## Output

- Periodic stats once per second: `Keys: total=1.23M, 456K/s`
- Matches: `FOUND: <base64>`

### Output comparison (C vs Rust)

```text
# C version (meshtastic_keygen)
Starting key generation with 8 threads...
Keys: total=733K, 367K/s
FOUND: Q0xGdlpBQkM0Rk1yS1p5M0pzSjY4M0Y2WmE9

# Rust version (Rust/meshtastic_keygen_rs)
Start: 2025-10-01 12:34:56+00:00
Keys: total=732K, 366K/s
FOUND: Q0xGdlpBQkM0Rk1yS1p5M0pzSjY4M0Y2WmE9
Done. Elapsed: 3.002s | total keys: 2.19M | found: 1 | rate: 730K/s
```

Notes:

- Exact numbers will vary by CPU and flags. The Rust build above used `--release`.
- The Rust version prints a start timestamp and a final summary line.

## Notes

- Uses OpenSSL 3 APIs (EVP_PKEY_X25519, get_raw_private_key).
- The process runs indefinitely; stop with Ctrl-C.

## License

This project is released under the WTFPL v2.

```text
            DO WHAT THE F*CK YOU WANT TO PUBLIC LICENSE
                        Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE F*CK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE F*CK YOU WANT TO.
```
