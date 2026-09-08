# Hardware SHA Acceleration for SLH-DSA on the Nano ESP32

This document covers the hardware-accelerated signing path added to `nano-signer`: what was built, why it's built the way it is, how to run every test involved, and every issue hit along the way (including the ones that turned out to be wrong turns, not just the ones that panned out).

Status: **implemented, built, flashed, and cross-verified on real hardware.** All three of `Sha2L1` (128s/128f), `Sha2L35`'s `h_msg`, and `Sha2L35`'s `prf_msg` are now hardware-backed, alongside the original `f`/`prf_sk`/`h`/`t` path. The `hw-sha` feature has actually compiled for the real `xtensa-esp32s3-none-elf` target (this sandbox still can't do that itself; see section 3.3), `t` has been run on real hardware for `128s`/`128f`/`192f` with results in `BENCHMARKING.md`, and a device-generated `192f` signature has been decoded and verified successfully against `cli`'s independent `slh-dsa 0.1.0` implementation, the real proof that the hardware-hashing path produces cryptographically correct output, not just "didn't crash." Two real bugs were caught before/during this (see "Issues encountered" items 11 and 12); nothing further has been reported broken since. What's not yet done: `192s`/`256s`/`256f` haven't been benchmarked or cross-verified, and Phase 7 (SD card) still doesn't exist, so getting a signature off the device for cross-verification is still a manual hex-copy-and-decode process (section 3.7).

---

## 1. What this is and why it's built this way

The goal: make `nano-signer`'s SLH-DSA signing actually use the ESP32-S3's SHA hardware peripheral, instead of the pure-software `sha2` crate `slh-dsa` calls by default. Raw hardware-vs-software hashing was already benchmarked before this work started (see `BENCHMARKING.md`'s "Raw hashing" table); hardware won decisively, ~7-8x faster even at the small (100-200 byte) input sizes SLH-DSA's hash calls actually use. The question this phase answers is whether that raw win translates into faster real signing.

### Fork vs. from-scratch

`INSTRUCTIONS.md` in this repo is a complete from-scratch FIPS 205 implementation spec (all 25 algorithms, 12 parameter sets, KAT vector validation, side-channel hardening). It was evaluated and explicitly **not** used as the implementation path here. Reasoning:

- KAT (known-answer test) vectors are required to trust a from-scratch SLH-DSA implementation, and this sandbox has no way to fetch or independently validate the official ones.
- RustCrypto's `slh-dsa` is already a correct, tested implementation. Reimplementing 25 algorithms to add one hardware backend would throw away that correctness for no benefit.
- The actual blocker (making a single hardware SHA peripheral usable where the crate expects cheap, repeated `Sha256::new()`-style construction) is a small, targeted problem. It doesn't require rewriting the signature scheme around it.

So the approach taken: **fork `slh-dsa` locally and edit its internals directly**, rather than trying to fit a hardware backend through the crate's public API from outside. This sidesteps a real blocker described in `TODO.md` Phase 6: `esp_hal::sha::ShaDigest` implements `digest::Update`/`FixedOutput`/`OutputSizeUser`/`HashMarker`, but not `Default`, and RustCrypto's blanket `impl<D: FixedOutput + Default + Update + HashMarker> Digest for D` needs `Default`. Since a hardware peripheral is a singleton, `Default::default()` can't safely construct one. Trying to satisfy that trait bound from outside the crate would have meant either an unsafe global side-channel or convincing upstream to accept a redesigned, pluggable-hash-backend `HashSuite` trait. Editing the fork's own internals sidesteps this entirely: `hashes/sha2.rs` doesn't need `ShaDigest: Digest` at all, it just needs a type with `f`/`h`/`t`/`prf_sk` methods, and those can call whatever hardware API actually exists.

### What actually got forked

`slh-dsa 0.2.0-rc.5` (the exact version `nano-signer` already depended on) was vendored in full into `slh-dsa-hw/` (copied from `~/.cargo/registry/src/.../slh-dsa-0.2.0-rc.5/`, via a disposable scratch Cargo project used only to force Cargo to download and cache the exact source; see "Issues encountered" for why this approach was used over the FIPS 205 PDF or web search). The package's `[package] name` stays `"slh-dsa"`, so `nano-signer/Cargo.toml` just points at it via a `path` dependency and nothing else in the codebase (imports, type names) had to change.

---

## 2. Architecture

### Scope: which parameter sets got hardware

`slh-dsa` has two `HashSuite` implementations for the SHA2 parameter family, and **both are now fully hardware-backed** under `hw-sha`:

- `Sha2L1<N, M>` backs `Sha2_128s`/`Sha2_128f`. Everything in this suite is SHA-256 (no SHA-512 split), so `prf_msg`/`h_msg` get the same hardware treatment as `f`/`prf_sk`/`h`/`t`.
- `Sha2L35<N, M>` backs `Sha2_192s`/`Sha2_192f`/`Sha2_256s`/`Sha2_256f`. `f`/`prf_sk` use hardware SHA-256, `h`/`t`/`h_msg` use hardware SHA-512, and `prf_msg` uses a hand-rolled HMAC-SHA-512 built around the hardware SHA-512 primitive (esp-hal has no hardware HMAC wrapper).

This wasn't the original scope. `Sha2L1` was initially left untouched (always software) and `Sha2L35`'s `prf_msg`/`h_msg` were initially left on software `sha2`/`hmac`, on the reasoning that `f`/`prf_sk`/`h`/`t` are the calls that happen tens of thousands of times per signature (per the byte-size table in `TODO.md` Phase 6) while `prf_msg`/`h_msg` happen exactly once, so accelerating them didn't seem worth the added complexity.

**That reasoning was wrong, and real measurements caught it.** Once `f`/`h`/`t`/`prf_sk` were hardware-accelerated, an on-device `192f` benchmark run showed timing that scaled almost perfectly linearly with message length (flat ~1740ms up to a few hundred bytes, climbing to 8027ms at the corpus's largest 65,536-byte message), where it had previously been dominated by the (message-length-independent) tree/FORS traversal cost. `h_msg`/`prf_msg` "happen once per signature" is true, but their *cost* scales with the signed message's length, not just their call count; once everything else got faster, that stopped being negligible. Working out the throughput from the scaling portion of that run gave roughly 10.4 KB/sec for the software SHA-512 path, an oddly slow number that (independent of the decision to accelerate it) is itself worth a closer look someday, most likely tied to this project's `opt-level = "s"` build profile interacting badly with SHA-512's larger round count and 64-bit working state on a 32-bit core. `Sha2L1` was brought in at the same time since the same argument applies to it and it's the simpler case (no SHA-256/SHA-512 split, so `prf_msg`/`h_msg` reuse the exact same hardware SHA-256 machinery as everything else in that suite).

### The singleton problem, and how it's solved

The ESP32-S3 has exactly one SHA peripheral. `esp_hal::init()` hands it out exactly once, as `peripherals.SHA`. `slh-dsa`'s `HashSuite` trait methods (`f`, `h`, `t`, `prf_sk`) take `&self`, not any kind of peripheral handle, so there's no way to thread the peripheral through the public API without changing that trait's signature (which would ripple through every other file in the crate: `wots.rs`, `xmss.rs`, `hypertree.rs`, `fors.rs`).

Solution: a global, `critical_section`-guarded static inside the fork itself (`slh-dsa-hw/src/hashes/hw.rs`):

```rust
static HW_SHA: Mutex<RefCell<Option<Sha<'static>>>> = Mutex::new(RefCell::new(None));

pub fn init_hw_sha(sha: Sha<'static>) { /* stores it */ }
fn with_hw_sha<R>(f: impl FnOnce(&mut Sha<'static>) -> R) -> R { /* locks, unwraps, calls f */ }
```

`nano-signer`'s `main()` calls `slh_dsa::init_hw_sha(Sha::new(peripherals.SHA))` once at boot, before the main command loop. Every hardware-backed `HashSuite` method (and the standalone `slh_dsa::hw_sha256()` benchmarking helper used by the `'2'` serial command) goes through `with_hw_sha`, which panics with a clear message if `init_hw_sha` was never called. A `--no-default-features` (software-only) build of `slh-dsa-hw` never touches this static at all and doesn't need `init_hw_sha` called, though `nano-signer`'s `main.rs` calls it unconditionally regardless of which `param-*` feature is active, since it's cheap and harmless either way.

This is the same "safe singleton" shape `TODO.md` Phase 6 originally sketched as "Layer 1," just implemented inside the fork instead of as a separate crate, since forking made a separate layer unnecessary.

### Replicating the cached-midstate optimization in hardware

This is the one place this implementation ended up more involved than the original plan, and also where it turned out better than expected. Every `f`/`h`/`t`/`prf_sk` call in FIPS 205 starts by hashing `pk_seed` (zero-padded to exactly one hash block) before the ADRS/message bytes; that prefix is identical for every call made against the same key. `slh-dsa 0.2.0-rc.5`'s software implementation already exploits this: `Sha2L35::new_from_pk_seed()` hashes the prefix once into a `Sha256`/`Sha512` instance, stores it in `cached_hasher_256`/`cached_hasher_512` fields, and every `f`/`h`/`t`/`prf_sk` call does `self.cached_hasher_256.clone().chain_update(...)` instead of rehashing the prefix from scratch. (This was initially believed to be missing, per `TODO.md`'s pre-existing notes, which had been written against `slh-dsa 0.1.0`'s source, not the `0.2.0-rc.5` `nano-signer` actually depends on. See "Issues encountered.")

Replicating this for hardware initially looked possible via the peripheral's state save/restore support: `esp_hal::sha::Context<A>` plus `ShaDigest::save`/`restore`, discovered by reading `esp-hal 1.1.2`'s actual `sha.rs` source. That design shipped in an earlier revision of this fork, but **failed on the first real compile against the actual target** (this sandbox has no `xtensa` toolchain, so this could only be caught by a real build, done separately on real hardware): `Context<A>` derives `Clone`/`Debug`, and `#[derive(...)]` macros add a bound on the generic parameter itself (`A: Clone`, `A: Debug`) rather than analyzing that the field is only `PhantomData<A>` and doesn't structurally need it. esp-hal's `Sha256`/`Sha512` marker types are plain unit structs with no `Clone`/`Debug` impls, so `Context<Sha256>: Clone` is never satisfiable for any real algorithm, and the "clone the cached context per call" step couldn't compile. See "Issues encountered" item 11 for the full error and how it was found.

**Fix, and the design actually shipped:** drop `Context`/save/restore entirely. `HwPrefix256`/`HwPrefix512` (`slh-dsa-hw/src/hashes/hw.rs`) instead store the assembled one-block `pk_seed || zero-padding` prefix as plain bytes (`[u8; 64]`/`[u8; 128]`, always exactly one hash block by construction), and every `f`/`h`/`t`/`prf_sk` call re-hashes that prefix from scratch before the ADRS/message parts, using a fresh `ShaDigest::new(sha)` each time. This gives up the "cache the midstate, skip rehashing the prefix" optimization the software path has; it does not give up hardware acceleration itself, since the whole call, prefix included, still runs on the peripheral rather than in software. The extra cost is re-hashing one 64- or 128-byte block per call, on hardware that processes each block in low single-digit microseconds per the `'1'`/`'2'` benchmark. This is deliberately the same, simpler shape already proven correct by that benchmark: `ShaDigest::new`/`update`/`finish` only, no `Context`, no `Clone` bound to satisfy.

The hardware `Sha2L35` variant's `f`/`h`/`t`/`prf_sk` methods (`slh-dsa-hw/src/hashes/sha2.rs`) are structurally identical to the software ones, just calling `self.hw_prefix_256.hash([...])`/`self.hw_prefix_512.hash([...])` instead of `self.cached_hasher_256.clone().chain_update(...).finalize()`. Truncation to `N` bytes is done in Rust after getting the full 32/64-byte digest back from hardware (`&hash[..N]`), matching the software path's `&hash[..Self::N::USIZE]` exactly, rather than relying on the peripheral's own "short hash" support (asking it for fewer than the full digest length). That peripheral feature exists and is documented, but this implementation deliberately doesn't depend on it: there was no way to verify in this sandbox that a hardware short-hash output is bit-identical to a full hash truncated by hand, and getting that wrong would silently produce wrong signatures. Always requesting the full digest and truncating in code removes that whole question.

### Hardware `h_msg` and hand-rolled hardware HMAC

`h_msg` has no fixed prefix to cache (its first input, the per-signature randomizer, differs on every call), so it's just a one-shot hardware hash: `hw_hash256`/`hw_hash512` in `hw.rs` feed a list of parts to a fresh `ShaDigest` and return the full digest, no `HwPrefix*` involved.

`prf_msg` is HMAC, and esp-hal has no hardware HMAC wrapper, so `hw_hmac_sha256`/`hw_hmac_sha512` build the standard construction by hand around the one-shot hash functions: `H((K^opad) || H((K^ipad) || message))`, with `K` zero-padded to the block size (64 bytes for SHA-256, 128 for SHA-512). This is safe to do by hand here specifically because every HMAC key in this crate (`sk_prf`) is at most 32 bytes, always shorter than either block size, so the "hash the key down first" case the full HMAC spec requires for over-long keys never applies and was not implemented.

### Feature wiring

`slh-dsa-hw/Cargo.toml` adds:

```toml
[features]
hw-sha = ["dep:esp-hal", "dep:critical-section", "dep:nb"]
```

`esp-hal`, `critical-section`, and `nb` are optional dependencies, pulled in only when `hw-sha` is enabled, so a plain `cargo build` of `slh-dsa-hw` with no features (or `--features alloc` for the original crate's own test suite) still builds on a normal host target with no ESP32 toolchain at all. This was actually exercised: `cargo build --no-default-features` (matching exactly the feature set `nano-signer` uses when `hw-sha` is off) builds cleanly on this machine's host target. See "Issues encountered" for what could and couldn't be verified this way.

`nano-signer/Cargo.toml` now depends on the fork:

```toml
slh-dsa = { path = "../slh-dsa-hw", default-features = false, features = ["hw-sha"] }
```

---

## 3. How to run each test

### 3.1 Desktop CLI tests (unaffected by this work, unchanged)

```bash
cd cli
cargo test
```

This exercises `cli`'s own `slh-dsa 0.1.0` dependency (a separate crate version from `nano-signer`'s fork, always has been), so it's a good sanity check that the general SLH-DSA round-trip logic (`generate_keypair`/`sign_message`/`verify_message`) still works, but it does not touch the hardware fork at all.

### 3.2 Vendored fork, software path, host-buildable sanity check

This is the one part of the hardware work that actually could be verified in this sandbox. It confirms the `hw-sha`-gating edits didn't break the existing software implementation.

```bash
cd slh-dsa-hw
cargo build --no-default-features
```

Expected: builds cleanly (confirmed while writing this). This uses the exact feature set `nano-signer` uses for the software (non-`hw-sha`) path. It does **not** need `--features alloc` (`nano-signer` builds with `default-features = false` and no `alloc`, same as it always did against the crates.io version).

If you want to also run the fork's own unit tests (`hashes.rs`'s `prf_msg`/`h_msg` known-answer checks against fixed test vectors, and `lib.rs`'s sign/verify round-trip tests):

```bash
cargo test --features alloc,pkcs8/alloc
```

(`alloc` alone isn't enough; `pkcs8/alloc` has to be enabled alongside it or `signing_key.rs`/`verifying_key.rs`'s PKCS8 DER encoding functions fail to compile, since they need `der`/`pkcs8`'s own `alloc`-gated types. This was hit and diagnosed while sanity-checking the fork; see "Issues encountered.")

### 3.3 Vendored fork, hardware path: **cannot be built in this sandbox**

```bash
cd slh-dsa-hw
cargo build --no-default-features --features hw-sha
```

Attempted here, and fails for an expected, unrelated-to-this-work reason: `esp-hal`'s dependency chain (specifically `esp-sync`) uses `#![feature(asm_experimental_arch)]`, a nightly-only Rust feature gated behind the actual Xtensa target, and needs the `xtensa_lx` crate, which is only available when actually targeting an Xtensa chip. There is no `xtensa-esp32s3-none-elf` target installed in this sandbox, and no way to install the Espressif Rust toolchain fork here. **This command needs to be run for real on your machine, with the ESP toolchain installed** (the same one you'd use for any `nano-signer` build).

This has, in fact, already been run for real, twice, by the person building this. The first attempt caught a real bug: an earlier revision of `hw.rs` used `esp_hal::sha::Context`'s save/restore support to cache the `pk_seed`-prefix midstate, and that failed to compile (`Context<Sha256>: Clone` unsatisfiable; see "Issues encountered" item 11) for a reason no amount of source-reading in this sandbox surfaced, since it's a derive-macro trait-bound subtlety, not a missing or misused API. That was fixed (section 2's "Fix, and the design actually shipped"), rewriting `hw.rs` to only use `ShaDigest::new`/`update`/`finish`, the same three calls already proven correct by the `'1'`/`'2'` raw-hashing benchmark.

**The second attempt, after that fix plus the `Sha2L1`/`h_msg`/`prf_msg` hardware additions in section 2, built successfully with no further compiler-caught issues reported.** That's a real, confirmed data point now, not a prediction: `t` has been run on real hardware for `128s`/`128f`/`192f` (results in `BENCHMARKING.md`), and a device-produced `192f` signature has been cross-verified against `cli`'s independent implementation (section 3.7). The one bug that *would* have been caught here (item 12, the `hw_hmac_sha256`/`hw_hmac_sha512` lifetime issue) was found by review before this build, not by it, so this build's success is some evidence that review-without-a-compiler can work, not proof it always will. `192s`/`256s`/`256f` have not yet been built, run, or cross-verified; treat those three specifically as still resting on source-reading alone until someone actually runs them.

### 3.4 Building and flashing `nano-signer` (hardware path, the default)

Same as the existing workflow in `README.md`, since the fork is a drop-in replacement:

```bash
cd nano-signer
cargo build --release --no-default-features --features param-192f
espflash flash --monitor target/xtensa-esp32s3-none-elf/release/nano-signer
```

(`param-192f` is also the crate default, so plain `cargo build --release` picks it up too; being explicit here since `192f` is specifically the parameter set that gets the hardware path.)

Press `?` first to confirm `profile=release`. Then:

- **`s`**: sign the hardcoded test message. Same behavior as before this work; internally now uses the hardware-backed `HashSuite` for the `192f` default.
- **`t`**: benchmark all 100 corpus messages. This is the number that actually answers "did hardware acceleration help real signing," and it has now been run: `BENCHMARKING.md`'s Results table has real hardware rows for `128s`/`128f`/`192f`, each next to its pre-hardware software baseline for direct comparison (`192f` alone went from a 76807-83095 ms range down to 1708-1726 ms). `192s`/`256s`/`256f` haven't been run yet; do the same thing for those if you want the full picture.
- **`k`**: on-device keygen. Also exercises the hardware path via `new_from_pk_seed`.
- **`1`** / **`2`**: raw software vs. hardware SHA-256 throughput, unrelated to signing itself but sharing the same underlying SHA peripheral singleton (see below). Numbers already on record in `BENCHMARKING.md`.

### 3.5 Building `nano-signer` in pure software, for a direct before/after comparison

`slh-dsa-hw`'s `hw-sha` feature is not a crate default (`slh-dsa-hw`'s own `[features] default` is unchanged from upstream: `alloc` + `pkcs8/alloc`, no `hw-sha`), but `nano-signer/Cargo.toml` requests it explicitly. To build `nano-signer` against the fork with hardware disabled, for a same-fork, same-toolchain, hardware-vs-software comparison, edit `nano-signer/Cargo.toml`'s `slh-dsa` line to drop `features = ["hw-sha"]`:

```toml
slh-dsa = { path = "../slh-dsa-hw", default-features = false }
```

then build and flash exactly as in 3.4, and run `t` again. This isolates the hardware-vs-software difference from the fork itself (no other code changed between the two runs), which is a cleaner comparison than the current `BENCHMARKING.md` baseline (that baseline was measured against the *unforked* crates.io `slh-dsa`, not this fork with `hw-sha` off; the two should behave identically, since the software path in the fork is a byte-for-byte copy of upstream, but a same-fork comparison removes even that assumption).

### 3.6 Note on `Cargo.lock`

`nano-signer/Cargo.lock` and `slh-dsa-hw`'s registry-generated `Cargo.lock` were both left for Cargo to regenerate on the next real build; `Cargo.toml` changed enough (new path dependency, `sha2`/`digest` version bump) that the existing lock is stale. This isn't a manual step: `cargo build` updates the lock automatically to match `Cargo.toml` unless run with `--locked`/`--frozen`. If you do run with either of those flags out of habit, drop them for the first build after this change.

### 3.7 Cross-verifying a device signature against the desktop CLI

`s` now prints the full signature hex rather than truncating to 8 bytes, specifically so it can be checked against an independent implementation rather than just trusting that signing didn't crash. This is the real test of hardware-hashing correctness; the on-device sign/verify round trip alone isn't, since signing and verifying both go through the same hardware `HashSuite` and would round-trip successfully even if that suite were consistently wrong in the same way both times.

**This has been done, successfully.** A `192f` signature produced by the hardware-backed device was decoded and verified against `cli`'s independent `slh-dsa 0.1.0` implementation and passed. That's the actual proof point this whole effort was building toward: not just "faster," but confirmed cryptographically correct against code this fork never touched. Two real, practical snags came up doing it the first time; both are folded into the steps below and also logged in "Issues encountered" items 13-14.

You need less than it looks like:

- **Public key**: don't copy it. `nano-signer/keys/pub.key` is already on disk, raw bytes, exactly what `cli verify` wants.
- **Message**: don't copy it either. `cli verify`'s `<message>` argument is a literal string (`message.as_bytes()` in `cli/src/main.rs`), not a file, and the device always signs the hardcoded constant `b"hello from the nano-signer bring-up test"`. Pass that exact string.
- **Signature**: this is the only thing that has to come off the device.

Steps:

1. Capture the whole serial session to a file rather than copying out of a live terminal scrollback. On macOS: `script capture.log espflash flash --monitor target/xtensa-esp32s3-none-elf/release/nano-signer`, then press `s`. Don't try to select and copy the hex directly out of the terminal window; a single ~70,000-character line is exactly the shape that silently gets truncated by terminal scrollback/selection limits (see item 13).
2. Pull the hex string after `signature (N bytes):` out of `capture.log` into its own file, e.g. `sig_hex.txt`, with no surrounding text or whitespace.
3. Sanity-check the copy before decoding: `wc -c sig_hex.txt` should read exactly `N * 2` (the byte count the device printed, doubled, since it's still hex text at this point). If it doesn't match exactly, the capture is incomplete; redo step 1 rather than proceeding.
4. Hex-decode it into real bytes: `xxd -r -p sig_hex.txt sig.bin` (`xxd` ships with Vim, already present on macOS; no new tooling needed). `wc -c sig.bin` should now read exactly `N`.
5. From `cli/`: `cargo run -- verify ../nano-signer/keys/pub.key "hello from the nano-signer bring-up test" ../sig.bin --param 192f` (swap `--param` to match whatever `nano-signer` was actually built with).

Step 3 and the second half of step 4 exist specifically because of items 13 and 14: skipping either byte-count check trades a clear, self-diagnosing failure ("this doesn't have the length it should") for `cli`'s generic `invalid signature at ...` error, which looks identical whether the problem is a bad capture, an un-decoded hex file, or an actual cryptographic mismatch. Checking the length before running `verify` at all removes that ambiguity.

One thing worth knowing going in: `cli` depends on `slh-dsa 0.1.0`; `nano-signer` depends on the `slh-dsa-hw` fork of `0.2.0-rc.5`. FIPS 205's signature encoding is a fixed, standardized byte layout, and this cross-verify succeeding confirms they are in fact wire-compatible for `192f`, at least for the one signature tested; this hasn't been separately re-confirmed for the other five parameter sets, though there's no reason to expect them to differ. If a future cross-verify fails, isolate before assuming it's a hardware bug: rebuild `nano-signer` with `hw-sha` off (see section 3.5, still the same `0.2.0-rc.5` fork, just pure software), capture that signature the same way, and verify it against `cli`. If the software-mode signature verifies but the hardware one doesn't, that points at the hardware path specifically rather than a version-mismatch red herring.

---

## 4. Issues encountered along the way

In roughly chronological order:

1. **FIPS 205 PDF text extraction completely failed.** The initial approach to find SLH-DSA's exact byte-size/call-count breakdown was to read the NIST FIPS 205 PDF directly. Both a WebFetch attempt and a manual Python (`zlib` + regex over PDF `Tj`/`TJ` text-drawing operators) extraction attempt failed; the PDF's font uses a CID/glyph-index encoding rather than direct ASCII text runs, so byte-level parsing without the font's ToUnicode CMap produced only whitespace. There was no `poppler-utils`/`pdftoppm` available either (`apt-get install` failed with a permission error, confirming no package-manager access in this sandbox). **Fix:** pivoted, at the user's explicit suggestion, to reading the actual RustCrypto `slh-dsa` crate source directly instead of the spec PDF. This turned out to be strictly better for this purpose: it's literally the code that runs, not a description of what code should do.

2. **No reliable way to fetch exact crate source versions via web tools.** Needed the *exact* source of `slh-dsa 0.2.0-rc.5` (a pre-release version, not always well-indexed by doc/search tools) and later `esp-hal 1.1.2`, `critical-section 1.2.0`. **Fix:** created disposable, host-target scratch Cargo projects (in the session scratchpad, not this repo) declaring the exact dependency, ran `cargo build`/`cargo fetch`, and read the result directly out of `~/.cargo/registry/src/index.crates.io-.../<crate>-<version>/`. This is now the established technique in this project for "what does this dependency actually do" questions; it's more reliable than web search or trusting training-data memory of a crate's API, especially for pre-release versions.

3. **A materially wrong assumption carried over from `slh-dsa 0.1.0` to `0.2.0-rc.5`.** Early research (and `TODO.md`'s Phase 6 notes) was based on reading `slh-dsa 0.1.0`'s source, including its byte-size-per-hash-call table and a note that the software implementation "recomputes that first \[pk_seed-prefix\] block from scratch each time rather than caching the midstate." `nano-signer` actually depends on `0.2.0-rc.5`, not `0.1.0`, and re-reading the *actual* dependency's source (step 2 above, applied to `slh-dsa` itself this time) showed `0.2.0-rc.5` already caches that midstate (`cached_hasher`/`cached_hasher_256`/`cached_hasher_512` fields, populated once via `new_from_pk_seed`, cloned per call). Presenting the "no caching" claim as a still-open optimization opportunity would have been false for the version this project actually uses. **Fix:** corrected in `TODO.md` Phase 6 (see that file's current text). An initial revision of this implementation also tried to replicate that same caching approach in hardware via the peripheral's save/restore support; that turned out not to compile for unrelated reasons (see item 11), so the hardware path ended up re-hashing the prefix per call after all, just still on hardware rather than software. This is also a case worth generalizing from regardless: crate behavior claims should be checked against the exact dependency version in use, not "the crate" in the abstract, especially pre-1.0 crates that can change materially between minor/rc versions.

4. **`sha2`/`digest` version mismatch silently broke a "same implementation" claim.** Earlier benchmarking work added `sha2 = "0.10"` / `digest = "0.10"` directly to `nano-signer/Cargo.toml`, on the assumption this would unify with whatever `slh-dsa` used internally, making the `'1'` (software) benchmark command "the same implementation used by signing." Checking `nano-signer/Cargo.lock` directly showed this was false: `slh-dsa 0.2.0-rc.5` actually depends on `sha2 0.11.0`/`digest 0.11.3`, and Cargo had resolved *two separate copies* (`0.10.x` and `0.11.x` of each) rather than unifying them, since `0.10`/`0.11` are semver-incompatible major-ish bumps for a pre-1.0 crate. **Fix:** bumped `nano-signer/Cargo.toml`'s `sha2` dependency to `"0.11"` (matching what the fork now needs anyway) and removed the direct `digest` dependency entirely, since `main.rs` no longer names `digest::` paths directly after the `'2'` command was rewritten to call `slh_dsa::hw_sha256()` instead of driving `esp_hal::sha::ShaDigest` by hand (see item 6 below). `sha2::Digest` (used by the `'1'` command) is a re-export from `sha2`, and doesn't need a direct `digest` dependency edge to use via that path.

5. **A previously wrong hedge about hardware performance.** Before real numbers existed, the expectation (recorded in `TODO.md` Phase 6 at the time) was that hardware might be a wash or even lose at SLH-DSA's small (under-200-byte) per-call input sizes, due to fixed hardware setup overhead per call. Real measured data (the `'1'`/`'2'` raw-hashing benchmark, confirmed run in `release` profile) showed hardware ~7-8x faster even at these sizes. This was wrong, and has been corrected in `TODO.md` and reflected in this document's design (item 3 in section 1 above: the raw-hashing win was real, which is what justified doing this work at all).

6. **Two independent SHA-peripheral handles would have conflicted.** `main.rs` already had its own `sha_peripheral = Sha::new(peripherals.SHA)` for the `'1'`/`'2'` raw-hashing benchmark commands, acquired directly in `main()`. Once the hardware-backed `HashSuite` needed its own access to the same physical peripheral (via `slh_dsa::init_hw_sha`), there was no way for both to hold a handle: `peripherals.SHA` can only be moved once. **Fix:** consolidated onto a single access path. `main()` now calls `slh_dsa::init_hw_sha(Sha::new(peripherals.SHA))` once at boot, and the `'2'` command was rewritten to call a new `slh_dsa::hw_sha256(data)` convenience function (also added to `hw.rs`) that goes through the same internal singleton, instead of holding a separate `Sha` instance in `main.rs`. This also means the `'2'` benchmark and real signing now measure contention against the same shared resource, which is arguably more representative than two independent handles would have been anyway.

7. **Whether the hardware peripheral supports the state save/restore needed to replicate midstate caching was investigated, looked resolved from source-reading alone, and then turned out not to work.** Initial design planning assumed the ESP32-S3's SHA peripheral might not support pausing and resuming a hash computation, and sketched a fallback of just rehashing the `pk_seed` prefix from scratch on every hardware call. Reading `esp-hal 1.1.2`'s actual `sha.rs` source (item 2's technique) found `esp_hal::sha::Context<A>` plus `ShaDigest::save`/`restore`, which looked like exactly the needed mechanism, so an earlier revision of this implementation used it instead of the fallback. It doesn't actually work: see item 11. The version described in section 2 above and actually shipped is the rehash-from-scratch fallback after all, just discovered to be necessary later than expected, and only by a real compiler.

8. **Whether `Sha<'d>`'s lifetime parameter could be made `'static` for storage in a global static was an open question, and resolved favorably.** A global singleton needs `'static` data. `esp_hal::sha::Sha<'d>` is generic over a lifetime tied to the underlying `SHA<'d>` peripheral token. Checking `esp-hal`'s `peripherals/mod.rs` (the macro-generated `Peripherals` struct) showed that `esp_hal::init()` returns `Peripherals` with every field typed as `<Name><'static>`, so `peripherals.SHA` is concretely `SHA<'static>`, and `Sha::new(peripherals.SHA)` is `Sha<'static>` with no unsafe lifetime extension needed. The static in `hw.rs` (`Mutex<RefCell<Option<Sha<'static>>>>`) relies on exactly this.

9. **A test invocation of the vendored fork's default features failed, for an unrelated reason to this work.** Sanity-checking the fork with `cargo build --no-default-features --features alloc` (intending to test just the `alloc` feature in isolation) failed with several `der`/`pkcs8` compile errors (`SecretDocument`, `Document` not found). This is because the upstream crate's real default is `["alloc", "pkcs8/alloc"]` together; enabling `alloc` alone, without also turning on `pkcs8`'s own `alloc` feature, leaves `signing_key.rs`/`verifying_key.rs`'s PKCS8 DER encoding code referencing types `pkcs8`/`der` only expose when *their* `alloc` feature is also on. This is a pre-existing characteristic of the upstream crate, not something introduced by this fork; `nano-signer` itself was never affected, since it builds with `default-features = false` and neither `alloc` nor `pkcs8/alloc` (SLH-DSA's stack-based API doesn't need heap allocation for the operations `nano-signer` actually uses). Documented in section 3.2 above so this doesn't need rediscovering.

10. **The `hw-sha` feature cannot be compiled in this sandbox**, as covered in section 3.3, and everything about the original design was checked against real source rather than a real compiler. That gap showed up almost immediately: see item 11.

11. **The `Context`-based midstate caching design didn't compile on the first real build, confirmed on real hardware.** Once `hw-sha` was actually built for real (`xtensa-esp32s3-none-elf`, `--release`), it failed with `E0277`/`E0599` errors: `the trait bound esp_hal::sha::Sha256: Clone is not satisfied`, `... doesn't implement Debug`, and `the method clone exists for struct Context<Sha256>, but its trait bounds were not satisfied`, all three repeated for `Sha512`. Cause: `esp_hal::sha::Context<A>` is declared `#[derive(Debug, Clone)]`. Rust's derive macros add a bound on the *type parameter itself* (here, `A: Clone`, `A: Debug`) rather than analyzing whether the actual fields need it; `Context<A>`'s only use of `A` is `PhantomData<A>`, which doesn't need `A: Clone` to itself be `Clone`, but the derive macro doesn't know that and adds the bound anyway. esp-hal's `Sha256`/`Sha512` (and every other `ShaAlgorithm` marker type) are generated as plain unit structs (`pub struct $name;`) with no `Clone`/`Debug` impl, so `Context<Sha256>: Clone` can never be satisfied, for any algorithm, in any consumer of this API. Reading the source correctly identified that `save`/`restore`/`Context` exist and do what their names suggest; it did not catch that the specific way this implementation intended to use them (`.clone()` a saved `Context` before each `restore()`, to reuse one cached prefix across many calls) is structurally impossible given how `Context` derives its traits. **Fix:** rewrote `HwPrefix256`/`HwPrefix512` to drop `Context`/`save`/`restore` entirely (see section 2's "Fix, and the design actually shipped" for the replacement). The lesson generalizes past this one bug: reading source correctly answers "does this API exist and what does it do," but derive-macro bound behavior, and other compiler-enforced constraints that aren't visible from a type's own definition in isolation, are the kind of thing only a real compiler catches. Treat everything else in this document that's marked "checked against source, not compiled" with the same level of remaining doubt until it's actually built.

12. **A lifetime bug in the first draft of `hw_hmac_sha256`/`hw_hmac_sha512`, caught by review rather than by a real compile this time.** The first version tried to feed the HMAC inner hash with `hw_hash256(core::iter::once(ipad.as_slice()).chain(parts))`, mirroring how call sites elsewhere in `sha2.rs` build a single chained iterator out of several parts. The difference: at those call sites (`t`, `h_msg`, etc.), every piece being chained together is a parameter of the *same* function, so the compiler is free to infer a short, mutually-compatible lifetime for the whole expression. Inside `hw_hmac_sha256<'a>`'s own body, `parts: impl IntoIterator<Item = &'a [u8]>` carries `'a` as a *generic parameter of that function itself*, rigid and possibly as long as `'static` from the function's own point of view (it has to work for whatever lifetime a caller instantiates it with), while `ipad` is a local stack array scoped to the function body. `.chain()` requires both sides to share exactly one `Item` type, which here would require the borrow checker to prove a local array outlives an arbitrary external lifetime, which it never can. This would have failed with something like `E0521` ("borrowed data escapes outside of function") or a lifetime-inference error, the same general class of "only a real compiler catches this" issue as item 11, just caught by re-reading the code with that lesson in mind instead of by an actual `rustc` invocation. **Fix:** feed `ipad` and `parts` to the hasher as two separate steps within one `with_hw_sha` closure, matching the pattern `HwPrefix256::hash`/`HwPrefix512::hash` already used correctly for their own cached-prefix-plus-parts case. This fix has since been confirmed by a real build (item 13); at the time it was made, it was reasoned through, not proven.

13. **The full `hw-sha` build (all six parameter sets' worth of hardware code, both rounds of changes) compiled successfully on the real target, with no further compiler-caught issues beyond items 11 and 12.** `slh-dsa-hw --features hw-sha` was built for real `xtensa-esp32s3-none-elf`, `nano-signer` was flashed, and `t` ran to completion for `128s`, `128f`, and `192f` (results in `BENCHMARKING.md`). This is the first real confirmation that the fixes for items 11 and 12 were actually correct, not just plausible, and that the newer `Sha2L1`/`h_msg`/`prf_msg` hardware code (which had never been through a compiler at all before this) has no further issues of the same kind. It does not confirm `192s`/`256s`/`256f`, which use the same code paths generically but haven't been built or run themselves.

14. **Getting a large signature off the device by hand surfaced two more real, practical issues, both during the first cross-verification attempt (section 3.7).** First: copying the ~70,000-character hex line directly out of a live terminal window silently truncated it, losing roughly 2,000 bytes' worth of hex from the middle of the copy with no error or warning from anything involved; this was only caught by noticing the resulting file's byte count (67,282) didn't match either a complete hex dump (71,328) or a decoded binary signature (35,664). **Fix:** capture the whole serial session to a file with `script` instead of copying out of the terminal, which avoids the terminal's rendering/clipboard path entirely. Second, after fixing that: the resulting file, now the correct length, was still the ASCII hex *text*, not decoded binary, since `cli` reads raw bytes directly (`fs::read`) and has no awareness that a file might be hex-encoded. `Signature::try_from` rejected it with a generic `invalid signature at message.sig` error, indistinguishable at a glance from an actual cryptographic failure. **Fix:** `xxd -r -p` to decode before verifying. Both fixes are folded into section 3.7's steps as explicit byte-count checks (`wc -c` should read exactly double the signature length before decoding, exactly the signature length after), specifically so a future attempt gets a clear "this file is the wrong size" signal instead of `cli`'s ambiguous parse error.

---

## 5. What's left

Done since the last revision of this section: `slh-dsa-hw --features hw-sha` has been built for the real target (item 13); `t` has been run on real hardware for `128s`/`128f`/`192f` with results in `BENCHMARKING.md`; and a device-produced `192f` signature has been cross-verified against `cli`'s independent implementation (section 3.7, item 14). What's still open:

- `192s`, `256s`, and `256f` haven't been built, benchmarked, or cross-verified at all. They use the same generic `Sha2L1`/`Sha2L35` hardware code as the three parameter sets that have been tested, so there's no specific reason to expect a problem, but "no specific reason to expect a problem" is exactly the confidence level item 11 had right before it didn't compile. Treat these three as unverified until someone actually runs them.
- The ~10.4 KB/sec software SHA-512 throughput observed before `h_msg`/`prf_msg` were hardware-accelerated (see the "Scope" discussion in section 2) is now moot for the hot signing path, but the underlying question, why software SHA-512 was that slow on this chip, was never actually answered. Worth a direct benchmark (same shape as `'1'`/`'2'`, just `Sha512` over larger buffers) if the answer matters for something else later.
- Phase 7 (SD card) still doesn't exist. Getting a signature off the device for cross-verification is currently a manual capture-hex-decode dance (section 3.7); an SD card would let the device just write `message.txt.sig` as raw bytes directly, which is both the actual intended production workflow and a much less error-prone verification path than what item 14 had to work around.
- If the numbers justify it, consider whether upstreaming a pluggable-hash-backend design to RustCrypto's `slh-dsa` is worth pursuing; not attempted here, since the fork as built is scoped narrowly (one hash suite, one chip) and a generic backend abstraction acceptable to upstream would be a substantially larger design effort on its own.
