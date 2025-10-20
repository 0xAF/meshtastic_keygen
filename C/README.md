# C version: Meshtastic Key Generator

This folder contains the original C implementation.

## Build

Requires OpenSSL and pthreads. Optional: OpenCL for GPU mode.

```sh
make                     # builds meshtastic_keygen (with OpenCL if available)
make OPENCL=0            # build without OpenCL support
make debug               # builds meshtastic_keygen_debug with -g -O0
# Optional SIMD builds (do not change defaults):
make simd-avx2           # adds -mavx2 -mbmi2 -madx
make simd-ifma           # adds -mavx512f -mavx512dq -mavx512ifma
 
# Optional: build and link against lib25519
make lib25519            # downloads and builds lib25519 locally, then links against it

# Notes for lib25519 build:
# - It fetches the latest release into C/third_party and builds an arch-specific package under build/amd64/package.
# - Our app will then prefer lib25519 for X25519 public-key derivation (basepoint*sk) when available.
# - We still use OpenSSL for everything else (CLI, RNG, etc.). This keeps the default build portable; lib25519 is opt-in.
# - Prereqs: python3, a C toolchain (gcc/clang), make. No system-wide install is performed.
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
    - Prefix variants: `STR/` and `STR+`
    - Suffix variants: `/STR=` and `+STR=`
  - `--gpu`, `-g`: Use the OpenCL GPU implementation (requires OpenCL runtime and `opencl_keygen.cl`). Implements the full X25519 Montgomery ladder and matches the CPU path (validated against RFC 7748).

### CPU internals and tuning

- Internal CPU ladder: You can optionally use the built-in Montgomery ladder instead of OpenSSL for public key derivation.
  - Enable via environment: `MEKG_CPU_INTERNAL=1`.
  - By default, it computes one inversion per key.

- Batched inversion (low-risk optimization): Amortize inversions by batching N keys at a time.
  - Enable by selecting a batch size > 1: `MEKG_CPU_BATCH=64` (or 128/256, etc.).
  - Requires `MEKG_CPU_INTERNAL=1`.
  - Flow: compute X2/Z2 for N clamped secrets, do one product-tree batch inversion for all Z2, then finish N pub keys.
  - Benefits: a single inversion per N keys; often a noticeable throughput bump on CPUs where inversion dominates.

- Experimental: small multi-lane batching scaffold (AVX2)
  - Gate: `MEKG_EXPERIMENTAL_AVX2_MULTI=2` or `4` (off by default).
  - Requires `MEKG_CPU_INTERNAL=1` and a CPU with AVX2 (detected at runtime).
  - Current behavior: uses the same per-key Montgomery ladder to produce X2/Z2 for 2 or 4 secrets, then performs a single batch inversion and completes those keys. This is a correctness-equivalent staging step for future true SIMD implementations.
  - Notes: This is an internal scaffolding feature intended for development/benchmarking. Expect little to no speedup yet; real gains will come once the FE math and ladder are vectorized.

Examples:

```sh
# Use internal ladder and batch inversion of 256 keys per batch
MEKG_CPU_INTERNAL=1 MEKG_CPU_BATCH=256 ./meshtastic_keygen -s AAA -t 16 -q

# Force a specific FE backend (optional): baseline|adx|avx2|ifma
MEKG_CPU_FE=adx MEKG_CPU_INTERNAL=1 MEKG_CPU_BATCH=128 ./meshtastic_keygen -s AAA -t 16 -q

# Build with ADX/BMI2 enabled (optional speedup on supporting CPUs)
make simd-avx2
MEKG_CPU_FE=adx ./meshtastic_keygen -s AAA -t 16 -q

# Try the experimental AVX2 multi-lane scaffold (2 lanes)
MEKG_CPU_INTERNAL=1 MEKG_EXPERIMENTAL_AVX2_MULTI=2 ./meshtastic_keygen -s AAA -t 16 -q
```

Notes:

- Batch sizes between 64 and 512 tend to work well; try 128 or 256 first and benchmark.
- Memory usage is modest: three arrays of `fe` structs sized to `MEKG_CPU_BATCH` per thread.
- Correctness is unchanged; FE tests and RFC 7748 tests pass with batching enabled.

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

## General notes

- `FOUND:` lines are printed to both stdout and stderr so you can watch for finds while redirecting stdout to a file. All other messages (start time, stats, final summary) are printed to stderr.
- Prints stats every 5 seconds (rate shown as keys per second) in human-readable units
- Emits a line per match: `FOUND: <base64>`
- Uses OpenSSL 3 APIs (EVP_PKEY_X25519, get_raw_private_key).
- The process runs indefinitely; stop with Ctrl-C.

## Safe GPU usage (OpenCL `-g`)

Some desktop GPUs and drivers can temporarily hang or reset if a compute kernel runs too long without yielding (this can also kill your GUI session). To keep runs stable on a desktop system:

- Start with conservative parameters and scale up gradually.
- Short kernels are safer; prefer more short dispatches over fewer long ones.

When `-g` is used, the tool prints the chosen OpenCL batch parameters. You can override them with command-line flags or environment variables.

CLI flags (highest precedence):

- `--gpu-gsize N`: Global work size (total work-items)
- `--gpu-lsize N`: Local work-group size
- `--gpu-iters N`: Iterations per work-item (kernel duration proxy)
- `--gpu-autotune`: Enable autotune to pick safe fast parameters automatically
- `--gpu-budget-ms N`: Autotune time budget per dispatch (ms)
- `--gpu-max-keys N`: Cap keys per single dispatch (global*iters) to avoid long kernels (default 1,048,576)

Environment variables (fallback):

- `MEKG_OCL_GSIZE`: Global work size (total work-items)
- `MEKG_OCL_LSIZE`: Local work-group size
- `MEKG_OCL_ITERS`: Iterations per work-item (kernel duration proxy)
- `MEKG_OCL_MAX_KEYS`: Cap keys per dispatch (global*iters). The host will split the batch into multiple aligned enqueues when exceeded.

Defaults (chosen to balance performance and responsiveness on desktop GPUs):

- `global=16384`, `local=128`, `iters=64`, `max_keys=1,048,576` (cap enforced by host-side chunking; iters capped at `<=512`)

Recommended ramp-up:

```sh
# Conservative starter (CLI flags)
./meshtastic_keygen -s 0xAF -b -c 1 -g --gpu-gsize 1024 --gpu-lsize 64 --gpu-iters 16

# If stable, increase iterations moderately (controls kernel length)
./meshtastic_keygen -s 0xAF -b -c 1 -g --gpu-iters 64

# If still stable, increase global size too
./meshtastic_keygen -s 0xAF -b -c 1 -g --gpu-gsize 16384 --gpu-lsize 128 --gpu-iters 64

# Env vars alternative (lower precedence than CLI)
MEKG_OCL_GSIZE=1024 MEKG_OCL_LSIZE=64 MEKG_OCL_ITERS=16 \
  ./meshtastic_keygen -s 0xAF -b -c 1 -g
```

Tips:

- Keep `local` to common multiples supported by your device (64/128/256).
- If the display stutters or the desktop resets, lower `MEKG_OCL_ITERS` first.
- For headless or compute-only sessions, you can push these higher, but test gradually.

New in this build: host-level chunking

- The app now enforces a per-dispatch cap on the number of keys (global*iters). If your requested `--gpu-gsize` and `--gpu-iters` exceed this cap, the run is split into multiple smaller dispatches aligned to `--gpu-lsize`.
- This keeps each kernel short and responsive on desktop GPUs, while still achieving large total throughput across many dispatches.
- Override the cap with `--gpu-max-keys` or `MEKG_OCL_MAX_KEYS` if you know your device can handle longer kernels.

Troubleshooting:

- If you see system logs indicating GPU resets (e.g. `amdgpu: ring ... timeout` or `device wedged`), reduce `MEKG_OCL_ITERS` and `MEKG_OCL_GSIZE`.
- Ensure your OpenCL runtime is installed and the kernel file `opencl_keygen.cl` is available in the working directory.

### Field multiply implementation (GPU math switch)

The OpenCL kernel supports two field multiplication variants for Curve25519:

- 51: 5×51 limbs using 128-bit emulation (stable baseline)
- 26: 10×(26/25) limbs using only 64-bit temporaries (often faster on GPUs)

Select at OpenCL program build time via an environment variable:

```sh
# Use the 26-bit variant
MEKG_OCL_FE_MUL=26 ./meshtastic_keygen -s AAA -g

# Force the 51-bit baseline
MEKG_OCL_FE_MUL=51 ./meshtastic_keygen -s AAA -g
```

Notes:

- If unset, the host defaults to 51 for maximum stability. You can opt into 26 to improve performance; both variants are validated for parity (TRACE/FE/RFC). Device-dependent speedups may vary.
- Autotune may choose parameters independent of this setting; you can combine both (e.g., enable autotune while forcing 26).

### Validation tests (optional)

Built-in checks you can trigger with environment variables:

```sh
cd C
make -s OPENCL=1

# 1) TRACE: step-by-step limb comparison (first 255 ladder steps)
MEKG_TEST_TRACE=1 ./meshtastic_keygen -g -q | sed -n '1,80p'

# 2) RFC 7748 basepoint public key test
MEKG_TEST_RFC=1 ./meshtastic_keygen -g -q

# 3) FE self-tests (randomized field op checks)
MEKG_TEST_FE=1 ./meshtastic_keygen -g -q

# Optional: run tests under the 26-bit mul path
MEKG_OCL_FE_MUL=26 MEKG_TEST_RFC=1 ./meshtastic_keygen -g -q

# 4) Deterministic PUB compare vs CPU (OpenSSL) for 256 samples
MEKG_TEST_PUB=1 ./meshtastic_keygen -g -q

# 5) Deterministic RNG (Philox) dump parity for 1024 samples
MEKG_TEST_RNG=1 ./meshtastic_keygen -g -q

# 6) Single known secret (hex) deep debug: compare CPU/GPU and dump ladder state
#    Provide a 32-byte secret as 64 hex chars (clamped internally)
MEKG_TEST_ONE_SK_HEX=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  ./meshtastic_keygen -g -q
```

### Optional: Autotune safe fast parameters

You can let the app quickly probe your GPU to pick safe, fast parameters automatically. Enable with either CLI or env:

```sh
# CLI
./meshtastic_keygen -s AAA -g --gpu-autotune

# or ENV
MEKG_OCL_AUTOTUNE=1 ./meshtastic_keygen -s AAA -g
```

By default, autotune limits each test dispatch to around 30ms to stay desktop-safe. You can change the budget:

```sh
# Try to find params within ~50ms per dispatch
./meshtastic_keygen -s AAA -g --gpu-autotune --gpu-budget-ms 50

# or ENV alternative
MEKG_OCL_AUTOTUNE=1 MEKG_OCL_AUTOTUNE_MS=50 ./meshtastic_keygen -s AAA -g
```

Notes:

- Autotune ignores your env overrides while probing, then prints and applies the selected values.
- `MEKG_OCL_ITERS` is still capped to a conservative maximum internally to avoid long-running kernels.
- CLI flags take precedence over environment variables for initial values; autotune, if enabled, will override both with its selection.

## CPU feature detection and benchmark

- At startup, the tool detects common x86 features (BMI2, ADX, AVX2, AVX‑512 IFMA) and prints a one-line summary unless `--quiet` is used. This prepares for future CPU-optimized backends.

- CPU-only benchmark mode: set an environment variable to run for a fixed duration and report throughput without configuring searches:

```sh
# Run for 3 seconds using 8 threads, quiet mode
cd C
make -s clean meshtastic_keygen
MEKG_BENCH_MS=3000 ./meshtastic_keygen -q -t 8
```

This mode uses the same generation pipeline as normal runs, but stops automatically after the specified milliseconds and prints total keys and keys/s.

### Notes

- The benchmark is CPU-only; it ignores `-g` and GPU flags.
- You can still use `--threads` and `--quiet` to control concurrency and logging.

### Selecting a CPU backend (optional)

You can force a specific CPU field backend for testing/benchmarks using an environment variable:

```sh
# Options: baseline | adx | avx2 | ifma (if supported by your CPU)
MEKG_CPU_FE=adx ./meshtastic_keygen -q -t 8 -s AAA -c 1
```

Auto-selection order (if not overridden): AVX‑512 IFMA first, then ADX+BMI2, then AVX2, otherwise baseline.

#### Backend status

- ADX/BMI2 backend: Implemented and selected automatically when supported; validated against RFC 7748 and FE self-tests. The implementation uses function multiversioning to stay portable by default and can benefit from ADX/BMI2 when available (or when building with `make simd-avx2`).
- AVX2 backend: Implemented functionally (scalar 5×51 path with identical reduction to baseline). Future work: exploit AVX2 to batch multiple ladders for throughput.
- AVX‑512 IFMA backend: Implemented functionally (scalar 5×51 path). Future work: replace with `_mm512_madd52lo/hi_epu64` for accelerated 5×51 mul on capable CPUs.
