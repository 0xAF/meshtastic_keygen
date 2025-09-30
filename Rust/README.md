# Meshtastic Key Generator (Rust)

A high-performance, multi-threaded X25519 private key generator/search tool written in Rust.

## Features

- Generates random 32-byte secrets per X25519 (with proper clamping)
- Base64 (STANDARD, with padding) encoding without allocations (encode_slice)
- Matches when Base64 starts with `STR` or ends with `STR=`
- Multi-threaded (per-thread SmallRng), minimal synchronization
- Periodic 5s reporter with human-readable totals and per-second rates
- Quiet mode (-q/--quiet) to disable periodic reporting

## Build

```sh
cd Rust
cargo build --release
```

## Usage

```sh
./target/release/meshtastic_keygen_rs --search STR [--search STR]... [--threads N] [--count C] [--quiet] [--better] [--affinity]
# or
./target/release/meshtastic_keygen_rs -s STR [-s STR]... [-t N] [-c C] [-q] [-b]
```

- `--search`, `-s` (required): Prefix string to search for in Base64. Can be specified multiple times.
  - Must contain only Base64 characters: A–Z, a–z, 0–9, +, /
  - Do not include '='; the tool will also match the suffix `STR=` automatically.
- `--threads`, `-t` (optional): Worker threads. Default: 4.
- `--count`, `-c` (optional): Stop after finding C matches. Default: 1.
- `--quiet`, `-q` (optional): Disable periodic reporting (5s stats).
- `--better`, `-b` (optional): Only match adjacent variants for nicer keys (base `STR` and `STR=` skipped):
  - Prefix variants: `STR/` and `STR+`
  - Suffix variants: `/STR=` and `+STR=`
- `--affinity` (optional): Pin worker threads to CPU cores (Linux)

### Examples

```sh
# Start 12 threads looking for 0xAF prefix or suffix 0xAF=
./target/release/meshtastic_keygen_rs -s 0xAF -t 12

# Only visually better variants (prefix: 0xAF/ and 0xAF+; suffix: /0xAF= and +0xAF=)
./target/release/meshtastic_keygen_rs -s 0xAF -b -t 12

# Stop after 5 matches
./target/release/meshtastic_keygen_rs -s 0xAF -c 5

# Quiet mode
./target/release/meshtastic_keygen_rs -s 0xAF -t 12 -q

# Save only matches to a file (FOUND lines)
./target/release/meshtastic_keygen_rs -s AAA -s ZZZ -t 12 1>matches.txt

Notes:
- `FOUND:` lines are emitted to both stdout and stderr for visibility while redirecting stdout to a file. Other messages (start, stats, summary) go to stderr.

```

## License

WTFPL v2.
