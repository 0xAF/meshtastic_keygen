# C version: Meshtastic Key Generator

This folder contains the original C implementation.

## Build

Requires OpenSSL and pthreads.

```sh
make            # builds meshtastic_keygen
make debug      # builds meshtastic_keygen_debug with -g -O0
```

## Usage

```sh
./meshtastic_keygen --search STR [--threads N] [--count C] [--affinity] [--quiet]
# or
./meshtastic_keygen -s STR [-t N] [-c C] [-q]
```

- `--search`, `-s` (required): Base64-only string [A-Za-z0-9+/] (no '='). Matches prefix or suffix `STR=`.
- `--threads`, `-t`: worker threads (default 4)
- `--count`, `-c`: stop after C matches (default 1)
- `--quiet`, `-q`: disable periodic reporting
- `--affinity`: pin worker threads to CPU cores (Linux)

### Examples

```sh
# Search for Base64 values that start with 0xAF or end with 0xAF=
./meshtastic_keygen -s 0xAF -t 12

# Minimal: default 4 threads
./meshtastic_keygen -s hello

# Stop after 5 matching keys
./meshtastic_keygen -s 0xAF -c 5
```

## Notes

- Prints stats every 5 seconds (rate shown as keys per second) in human-readable units
- Emits a line per match: `FOUND: <base64>`
- Uses OpenSSL 3 APIs (EVP_PKEY_X25519, get_raw_private_key).
- The process runs indefinitely; stop with Ctrl-C.
