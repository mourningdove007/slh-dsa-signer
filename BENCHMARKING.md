# Benchmarking

On-device SLH-DSA signing benchmark: for each parameter set, sign the same 100-message corpus and record the minimum, maximum, median, and average time across all 100. Covers three of the six FIPS 205 `SLH-DSA-SHA2-*` parameter sets: `128s`, `128f`, `192f`.

## Running the benchmarks

Generate the message corpus first if `nano-signer/messages/corpus.bin` doesn't already exist:

```bash
cd cli
cargo run -- gen-corpus ../nano-signer/messages/corpus.bin
```

Deterministic (SplitMix64, seed `20260902`); see "Message corpus" below for the exact format. Then, with `nano-signer` flashed and the serial monitor attached:

- **`t`**: signs all 100 corpus messages with the embedded key, timing each one. Blue LED on for the whole run; a progress line prints after each signature (index, message length, elapsed ms). On success, blue off and a final min/max/median/average line, then green for about half a second. On failure partway through, blue off, the failing message index, then red for about half a second, and no final summary line (an incomplete run isn't a valid data point):

  ```
  benchmarking 192f over 100 messages
  [  1/100] 10 bytes -> <N> ms
  [  2/100] 10 bytes -> <N> ms
  ...
  [100/100] 65536 bytes -> <N> ms
  192f over 100 messages: min <N> ms, max <N> ms, median <N> ms, average <N> ms
  ```

- **`1`** / **`2`** / **`3`**: each runs 1000 hashes (cycling 100-200 byte inputs) through one algorithm's software and hardware implementation back to back, printing both for direct comparison: `1` is SHA-256, `2` is SHA-512, `3` is HMAC-SHA-512 (a hand-rolled construction around the hardware SHA-512 primitive, since esp-hal has no hardware HMAC wrapper; see `NANO_DOCUMENTATION.md`). All three share the same SHA peripheral that signing itself uses, so results reflect real contention with whatever else touches it, not an isolated best case.

## Results

See `README.md` for the results table. The software rows predate the hardware backend added in `slh-dsa-hw/` (see `NANO_DOCUMENTATION.md`); kept there for direct comparison against the hardware rows rather than deleted. The 192f hardware row reflects the current implementation (`f`/`prf_sk`/`h`/`t`/`h_msg`/`prf_msg` all on hardware); an earlier, since-replaced measurement of 192f with only `f`/`prf_sk`/`h`/`t` hardware-accelerated showed a much wider min/max spread (1740-8027 ms) caused by `h_msg`/`prf_msg` still running in software and scaling with message length, which motivated hardware-accelerating those too.

## Raw hashing: hardware vs software

Results from the `'1'`/`'2'`/`'3'` commands described above; see `README.md` for the table. Hardware throughput is consistent across all three (5-13 million bytes/sec). Software throughput is not: SHA-256 in software (~2.1 million bytes/sec) is orders of magnitude faster than SHA-512 or HMAC-SHA-512 in software (~5,000-13,000 bytes/sec). The min/max spread within each SHA-512/HMAC-SHA-512 software row is not noise: it's a roughly fixed ~6,000 us cost per 128-byte block, and this input range straddles a 1-block/2-block boundary for SHA-512, so most samples land near the 2-block cost and a minority near the 1-block cost.

## Message corpus

| Field | Value |
|---|---|
| File | `nano-signer/messages/corpus.bin` (798,634 bytes) |
| Messages | 100: 50 lengths x 2 independently-random copies each |
| Lengths | 10 to 65,536 bytes, geometrically spaced |
| Record format | 4-byte little-endian length prefix + content, back to back |
| Generator | `cli gen-corpus` (`cli/src/lib.rs`), SplitMix64, seed `20260902` |

Geometric spacing covers the 3+ orders of magnitude range evenly; the two copies per length separate run-to-run jitter from an actual size trend. Regenerate with `cargo run -- gen-corpus <path>` from `cli/`; the same seed reproduces the file byte-for-byte.

