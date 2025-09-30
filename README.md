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

## Output

- Periodic stats once per second: `Keys: total=1.23M, 456K/s`
- Matches: `FOUND: <base64>`

### Output comparison (C vs Rust)

- On my Intel(R) Core(TM) i7-14700K with 28 cores and running 28 threads:
  - C: 770`K`/s
  - Rust: 53`M`/s

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
