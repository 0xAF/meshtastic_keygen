# C version: Meshtastic Key Generator

This folder contains the original C implementation.

## Build

Requires OpenSSL and pthreads. Optional: OpenCL for GPU mode.

```sh
make                     # builds meshtastic_keygen (with OpenCL if available)
make OPENCL=0            # build without OpenCL support
make debug               # builds meshtastic_keygen_debug with -g -O0
```

## Usage

```sh
./meshtastic_keygen --search STR [--search STR]... [--threads N] [--count C] [--affinity] [--quiet] [--better] [--gpu]
# or
./meshtastic_keygen -s STR [-s STR]... [-t N] [-c C] [-q] [-b] [-g]
```

- Options:
  - `--search`, `-s` (required, repeatable): Base64-only string [A-Za-z0-9+/] (no '='). When used without `-b`, matches prefix `STR` or suffix `STR=`.
  - `--threads`, `-t`: Worker threads (default 4)
  - `--count`, `-c`: Stop after C matches (default 1)
  - `--quiet`, `-q`: Disable periodic reporting (5s stats)
  - `--affinity`: Pin worker threads to CPU cores (Linux)
  - `--better`, `-b`: Only search for "visually better" adjacent variants around your pattern (the base `STR` and `STR=` are skipped):  
  - `--gpu`, `-g`: Use the experimental OpenCL GPU implementation (requires OpenCL runtime and `opencl_keygen.cl`). Currently a scaffold; the kernel returns placeholder results until the X25519 ladder is implemented.
    This keeps the requested `STR` but nudges it with Base64 boundary characters for nicer-looking keys.
    - Prefix variants: `STR/` and `STR+`
    - Suffix variants: `/STR=` and `+STR=`

### Examples

```sh
# Search for Base64 values that start with 0xAF or end with 0xAF=
./meshtastic_keygen -s 0xAF -t 12

# Only variants: match 0xAF/ and 0xAF+ (prefix), and /0xAF= and +0xAF= (suffix)
./meshtastic_keygen -s 0xAF -b -t 12

# Minimal: default 4 threads
./meshtastic_keygen -s 0xAF

# Stop after 5 matching keys
./meshtastic_keygen -s 0xAF -c 5

# Multiple patterns
./meshtastic_keygen -s AAA -s ZZZ -t 12

# Save only matches to a file (FOUND lines)
./meshtastic_keygen -s AAA -s ZZZ -t 12 1>matches.txt
```

## Notes

- `FOUND:` lines are printed to both stdout and stderr so you can watch for finds while redirecting stdout to a file. All other messages (start time, stats, final summary) are printed to stderr.
- Prints stats every 5 seconds (rate shown as keys per second) in human-readable units
- Emits a line per match: `FOUND: <base64>`
- Uses OpenSSL 3 APIs (EVP_PKEY_X25519, get_raw_private_key).
- The process runs indefinitely; stop with Ctrl-C.
