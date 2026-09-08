# Benchmarking

On-device SLH-DSA signing benchmark: for each parameter set, sign the same 100-message corpus and record the minimum, maximum, median, and average time across all 100. Covers three of the six FIPS 205 `SLH-DSA-SHA2-*` parameter sets: `128s`, `128f`, `192f`.

## Results

| Parameter set | Backend | Unit | Min | Max | Median | Average |
|---|---|---|---|---|---|---|
| 128f | software | ms | 2989 | 3048 | 2993 | 2997 |
| 128f | hardware | ms | 1010 | 1028 | 1011 | 1012 |
| 128s | software | ms | 62263 | 62322 | 62267 | 62272 |
| 128s | hardware | ms | 21061 | 21079 | 21062 | 21063 |
| 192f | software | ms | 76807 | 83095 | 76887 | 77573 |
| 192f | hardware | ms | 1708 | 1726 | 1709 | 1710 |


The software rows predate the hardware backend added in `slh-dsa-hw/` (see `NANO_DOCUMENTATION.md`); kept here for direct comparison against the hardware rows above rather than deleted. The 192f hardware row reflects the current implementation (`f`/`prf_sk`/`h`/`t`/`h_msg`/`prf_msg` all on hardware); an earlier, since-replaced measurement of 192f with only `f`/`prf_sk`/`h`/`t` hardware-accelerated showed a much wider min/max spread (1740-8027 ms) caused by `h_msg`/`prf_msg` still running in software and scaling with message length, which motivated hardware-accelerating those too.

## Raw hashing: hardware vs software

1000 hashes, cycling 100-200 byte inputs (`'1'` = software, `'2'` = hardware; see README.md).

| Backend | Min (us) | Max (us) | Median (us) | Average (us) | Throughput (bytes/sec) |
|---|---|---|---|---|---|
| Software (`sha2`) | 53 | 104 | 78 | 76 | 1,921,135 |
| Hardware (`esp_hal::sha`) | 8 | 13 | 11 | 10 | 12,891,810 |

## Hardware & build

| Field | Value |
|---|---|
| Board | Arduino Nano ESP32 |
| Chip | ESP32-S3 (u-blox NORA-W106 module) |
| CPU | Xtensa LX7 dual-core @ 240 MHz (max, via `CpuClock::max()`) |
| RAM | 512 KB SRAM |
| Flash | 16 MB |
| Build profile | `release` (`opt-level = "s"`, `lto = "fat"`, `codegen-units = 1`; overflow checks and debug assertions off) |
| Hashing | Hardware rows: ESP32-S3 SHA hardware accelerator via the `slh-dsa-hw` fork's `hw-sha` feature (on by default, all six parameter sets). Software rows: RustCrypto `sha2` only, no hardware; see `NANO_DOCUMENTATION.md` |


## Message corpus

| Field | Value |
|---|---|
| File | `nano-signer/messages/corpus.bin` (798,634 bytes) |
| Messages | 100: 50 lengths x 2 independently-random copies each |
| Lengths | 10 to 65,536 bytes, geometrically spaced |
| Record format | 4-byte little-endian length prefix + content, back to back |
| Generator | `cli gen-corpus` (`cli/src/lib.rs`), SplitMix64, seed `20260902` |

Geometric spacing covers the 3+ orders of magnitude range evenly; the two copies per length separate run-to-run jitter from an actual size trend. Regenerate with `cargo run -- gen-corpus <path>` from `cli/`; the same seed reproduces the file byte-for-byte.

