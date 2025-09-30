# Meshtastic Key Generator

A multi-threaded X25519 private key generator/search tool targeting Base64 prefixes/suffixes. Uses OpenSSL for keygen and Base64, and reports throughput once per second.

## Features

- Generates raw X25519 private keys and Base64-encodes them
- Matches when the Base64 string starts with a prefix or ends with the prefix plus '='
- Multi-threaded (user configurable)
- Periodic stats (1s): total keys and keys/sec in human-readable units

## Build

Requires OpenSSL (libssl and libcrypto) and pthreads.

```sh
make            # builds `meshtastic_keygen`
make debug      # builds `meshtastic_keygen_debug` with -g -O0
```

## Usage

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
