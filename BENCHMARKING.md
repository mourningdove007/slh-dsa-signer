# Benchmarking

On-device SLH-DSA signing benchmark: for each parameter set, sign the same 100-message corpus and record the minimum, maximum, median, and average time across all 100. Covers three of the six FIPS 205 `SLH-DSA-SHA2-*` parameter sets: `128s`, `128f`, `192f`.

## Results

| Parameter set | Min (ms) | Max (ms) | Median (ms) | Average (ms) |
|---|---|---|---|---|
| 128f | 2989 | 3048 | 2993 | 2997 |
| 128s | 62263 | 62322 | 62267 | 62272 |
| 192f | 76807 | 83095 | 76887 | 77573 |

## Hardware & build

| Field | Value |
|---|---|
| Board | Arduino Nano ESP32 |
| Chip | ESP32-S3 (u-blox NORA-W106 module) |
| CPU | Xtensa LX7 dual-core @ 240 MHz (max, via `CpuClock::max()`) |
| RAM | 512 KB SRAM |
| Flash | 16 MB |
| Build profile | `release` (`opt-level = "s"`, `lto = "fat"`, `codegen-units = 1`; overflow checks and debug assertions off) |
| Hashing | Software only (RustCrypto `sha2`), not the ESP32-S3's SHA hardware accelerator: `slh-dsa` calls `sha2` directly with no hook to hardware |


## Message corpus

| Field | Value |
|---|---|
| File | `nano-signer/messages/corpus.bin` (798,634 bytes) |
| Messages | 100: 50 lengths x 2 independently-random copies each |
| Lengths | 10 to 65,536 bytes, geometrically spaced |
| Record format | 4-byte little-endian length prefix + content, back to back |
| Generator | `cli gen-corpus` (`cli/src/lib.rs`), SplitMix64, seed `20260902` |

Geometric spacing covers the 3+ orders of magnitude range evenly; the two copies per length separate run-to-run jitter from an actual size trend. Regenerate with `cargo run -- gen-corpus <path>` from `cli/`; the same seed reproduces the file byte-for-byte.

