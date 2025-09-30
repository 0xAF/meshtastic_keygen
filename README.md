# Meshtastic Key Generator

A multi-threaded X25519 private key generator/search tool targeting Base64 prefixes/suffixes. Uses OpenSSL for keygen and Base64 in C, and reports throughput periodically.

## Implementations

- C version: see `C/` (build and usage: `C/README.md`)
- Rust version: see `Rust/` (build and usage: `Rust/README.md`)

## Features

- Generates raw X25519 private keys and Base64-encodes them
- Matches when the Base64 string starts with a prefix or ends with the prefix plus '='
- Multi-threaded (user configurable)
- Periodic stats (every 5s by default): total keys and keys/sec (per-second rate) in human-readable units
- Quiet mode (-q/--quiet) to disable periodic reporting

## Build

There are two implementations:

- C version in `C/` (depends on OpenSSL and pthreads)
- Rust version in `Rust/` (pure Rust)

## Key differences in Rust vs C version

- Uses Rust’s SmallRng and zero-allocation Base64 encoding into a fixed buffer
- Lock-free atomics for counters, clean shutdown via Ctrl-C
- Similar CLI: `-s/--search`, `-t/--threads`, `-c/--count`, `-q/--quiet`

## Output

- Periodic stats every 5 seconds (rate is per-second): `Keys: total=1.23M, 456K/s`
- Matches: `FOUND: <base64>`

### Performance comparison (C vs Rust)

- On my Intel(R) Core(TM) i7-14700K with 28 cores and running 28 threads:
  - C: 780 K/s
  - Rust: 445 K/s

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
