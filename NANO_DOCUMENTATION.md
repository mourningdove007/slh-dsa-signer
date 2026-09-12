# Hardware SHA Acceleration for SLH-DSA on the Nano ESP32

This document covers the hardware-accelerated signing path added to `nano-signer`: what was built, why it's built the way it is, and every issue hit along the way. Build/flash commands, serial command usage, and measured results live in `README.md` and `BENCHMARKING.md`; this document doesn't repeat those.

Status: **implemented, built, flashed, and cross-verified on real hardware.** `Sha2L1` (128s/128f) and `Sha2L35`'s `h_msg`/`prf_msg` are hardware-backed alongside the original `f`/`prf_sk`/`h`/`t` path. `t` has been run on real hardware for `128s`/`128f`/`192f` (results in `BENCHMARKING.md`), and a device-generated `192f` signature has been decoded and verified successfully against `cli`'s independent `slh-dsa 0.1.0` implementation, the real proof that the hardware-hashing path produces cryptographically correct output, not just "didn't crash." Two real bugs were caught along the way (items 11 and 12 below); nothing further has been reported broken since. Not yet done: `192s`/`256s`/`256f` haven't been benchmarked or cross-verified, and Phase 7 (SD card) still doesn't exist, so getting a signature off the device is still a manual hex-copy-and-decode process (section 3.1).

---

## 1. What this is and why it's built this way

The goal: make `nano-signer`'s SLH-DSA signing actually use the ESP32-S3's SHA hardware peripheral instead of the pure-software `sha2` crate `slh-dsa` calls by default. Raw hardware-vs-software hashing was benchmarked first (see `BENCHMARKING.md`'s "Raw hashing" table); hardware won decisively even at the small (100-200 byte) input sizes SLH-DSA's hash calls actually use, which is what justified this work.

### Fork vs. from-scratch

`INSTRUCTIONS.md` in this repo is a complete from-scratch FIPS 205 implementation spec. It was evaluated and explicitly **not** used here:

- KAT (known-answer test) vectors are required to trust a from-scratch implementation, and this sandbox has no way to fetch or independently validate the official ones.
- RustCrypto's `slh-dsa` is already a correct, tested implementation; reimplementing 25 algorithms to add one hardware backend would throw away that correctness for no benefit.
- The actual blocker, making a single hardware SHA peripheral usable where the crate expects cheap, repeated `Sha256::new()`-style construction, is a small, targeted problem that doesn't require rewriting the signature scheme around it.

So: **fork `slh-dsa` locally and edit its internals directly**, rather than fitting a hardware backend through the crate's public API from outside. This sidesteps a real blocker: `esp_hal::sha::ShaDigest` doesn't implement `Default` (a hardware peripheral is a singleton, so `Default::default()` can't safely construct one), which RustCrypto's blanket `Digest` impl requires. Editing the fork's own internals means `hashes/sha2.rs` never needs `ShaDigest: Digest` at all; it just needs a type with `f`/`h`/`t`/`prf_sk` methods that can call whatever hardware API actually exists.

### What actually got forked

`slh-dsa 0.2.0-rc.5` (the exact version `nano-signer` already depended on) was vendored in full into `slh-dsa-hw/`, copied from the Cargo registry cache via a disposable scratch project used only to force Cargo to download the exact source (see item 2 below). The package `[package] name` stays `"slh-dsa"`, so `nano-signer/Cargo.toml` points at it via a `path` dependency and nothing else in the codebase had to change.

---

## 2. Architecture

### Scope: which parameter sets got hardware

`slh-dsa` has two `HashSuite` implementations for the SHA2 parameter family, both now fully hardware-backed under `hw-sha`:

- `Sha2L1<N, M>` backs `Sha2_128s`/`Sha2_128f`. Everything in this suite is SHA-256, so `prf_msg`/`h_msg` get the same hardware treatment as `f`/`prf_sk`/`h`/`t`.
- `Sha2L35<N, M>` backs `Sha2_192s`/`Sha2_192f`/`Sha2_256s`/`Sha2_256f`. `f`/`prf_sk` use hardware SHA-256, `h`/`t`/`h_msg` use hardware SHA-512, and `prf_msg` uses a hand-rolled HMAC-SHA-512 built around the hardware SHA-512 primitive (esp-hal has no hardware HMAC wrapper).

This wasn't the original scope. `Sha2L1`, and `Sha2L35`'s `prf_msg`/`h_msg`, were initially left on software, on the reasoning that they're called once per signature (versus tens of thousands of times for `f`/`h`/`t`/`prf_sk`) so accelerating them didn't seem worth it. **That reasoning was wrong.** An on-device `192f` benchmark showed timing scaling almost linearly with message length once everything else was hardware-accelerated: `prf_msg`/`h_msg`'s cost scales with the *signed message's length*, not their call count, and that stopped being negligible once the rest got faster. See `SHA512.md` for the investigation this triggered into why software SHA-512 specifically was so slow.

### The singleton problem, and how it's solved

The ESP32-S3 has exactly one SHA peripheral, handed out once via `peripherals.SHA`. `slh-dsa`'s `HashSuite` trait methods take `&self`, not a peripheral handle, so there's no way to thread it through the public API without changing that trait's signature (which would ripple through `wots.rs`, `xmss.rs`, `hypertree.rs`, `fors.rs`).

Solution: a global, `critical_section`-guarded static inside the fork (`slh-dsa-hw/src/hashes/hw.rs`):

```rust
static HW_SHA: Mutex<RefCell<Option<Sha<'static>>>> = Mutex::new(RefCell::new(None));

pub fn init_hw_sha(sha: Sha<'static>) { /* stores it */ }
fn with_hw_sha<R>(f: impl FnOnce(&mut Sha<'static>) -> R) -> R { /* locks, unwraps, calls f */ }
```

`nano-signer`'s `main()` calls `slh_dsa::init_hw_sha(Sha::new(peripherals.SHA))` once at boot. Every hardware-backed method panics with a clear message if that never happened, rather than silently falling back to anything.

### Prefix caching: what was tried, what shipped

Every `f`/`h`/`t`/`prf_sk` call starts by hashing `pk_seed` (zero-padded to one block); that prefix is identical for every call against the same key, and the software implementation already caches it as a midstate. An attempt to replicate this in hardware via `esp_hal::sha::Context`'s save/restore support failed to compile on the first real build; see item 11 for the full story. **What shipped instead:** `HwPrefix256`/`HwPrefix512` (`slh-dsa-hw/src/hashes/hw.rs`) store the assembled prefix as plain bytes and re-hash it from scratch on every call via a fresh `ShaDigest`. This gives up that one optimization but keeps everything on hardware; the extra cost is one more 64- or 128-byte block per call, on hardware that processes a block in low single-digit microseconds.

Digests are always taken at full length and truncated in Rust, never via the peripheral's "short hash" option: there was no way to verify in this sandbox that a hardware short digest is bit-identical to a full digest truncated by hand, and getting that wrong would silently produce wrong signatures.

### Hardware `h_msg` and hand-rolled HMAC

`h_msg` has no fixed prefix to cache (its first input, the per-signature randomizer, differs every call), so it's a one-shot hardware hash. `prf_msg` is HMAC, and esp-hal has no hardware HMAC wrapper, so it's built by hand around the hardware primitive: `H((K^opad) || H((K^ipad) || message))`. This is only correct because every HMAC key here (`sk_prf`) is at most 32 bytes, always shorter than either hash's block size; the "hash an over-long key down first" case in the full HMAC spec isn't implemented, since it never applies.

### Feature wiring

```toml
# slh-dsa-hw/Cargo.toml
[features]
hw-sha = ["dep:esp-hal", "dep:critical-section", "dep:nb"]
```

Optional dependencies pulled in only when `hw-sha` is enabled, so `cargo build` with no features still builds on a normal host target with no ESP32 toolchain (confirmed; see item 9). `nano-signer/Cargo.toml` depends on the fork via `slh-dsa = { path = "../slh-dsa-hw", default-features = false, features = ["hw-sha"] }`.

---

## 3. Things not covered by README.md / BENCHMARKING.md

### 3.1 Cross-verifying a device signature against the desktop CLI

`s` prints the full signature hex specifically so it can be checked against an independent implementation, not just trusted to "not have crashed." This is the real test of hardware-hashing correctness; the on-device sign/verify round trip alone isn't, since signing and verifying both go through the same hardware `HashSuite` and would round-trip successfully even if that suite were consistently wrong in the same way both times.

**This has been done, successfully**: a `192f` signature produced by the hardware-backed device was decoded and verified against `cli`'s independent implementation. Two real, practical snags came up doing it the first time (items 13-14); both are folded into the steps below.

You need less than it looks like:

- **Public key**: don't copy it. `nano-signer/keys/pub.key` is already on disk, raw bytes, exactly what `cli verify` wants.
- **Message**: don't copy it either. `cli verify`'s `<message>` argument is a literal string, and the device always signs the hardcoded constant `b"hello from the nano-signer bring-up test"`.
- **Signature**: this is the only thing that has to come off the device.

Steps:

1. Capture the whole serial session to a file rather than copying out of a live terminal scrollback (a single ~70,000-character line silently gets truncated by terminal selection limits). On macOS: `script capture.log espflash flash --monitor target/xtensa-esp32s3-none-elf/release/nano-signer`, then press `s`.
2. Pull the hex string after `signature (N bytes):` out of `capture.log` into its own file, e.g. `sig_hex.txt`.
3. Sanity-check before decoding: `wc -c sig_hex.txt` should read exactly `N * 2`. If not, the capture is incomplete; redo step 1.
4. Hex-decode: `xxd -r -p sig_hex.txt sig.bin`. `wc -c sig.bin` should now read exactly `N`.
5. From `cli/`: `cargo run -- verify ../nano-signer/keys/pub.key "hello from the nano-signer bring-up test" ../sig.bin --param 192f`.

`cli` depends on `slh-dsa 0.1.0`; `nano-signer` depends on the `slh-dsa-hw` fork of `0.2.0-rc.5`. This cross-verify succeeding confirms the two are wire-compatible for `192f`, at least for the one signature tested. If a future cross-verify fails, isolate before assuming a hardware bug: rebuild with `hw-sha` off (section 3.3), capture that signature the same way, and verify it. If the software-mode signature verifies but the hardware one doesn't, that points at the hardware path specifically.

### 3.2 Vendored fork, software path: host-buildable sanity check

The one part of the hardware work that's actually verifiable in this sandbox:

```bash
cd slh-dsa-hw
cargo build --no-default-features
```

This uses the exact feature set `nano-signer` uses for its software path, and confirms the `hw-sha`-gating edits didn't break it. To also run the fork's own unit tests: `cargo test --features alloc,pkcs8/alloc` (`alloc` alone isn't enough; see item 9).

### 3.3 Building `nano-signer` in pure software, for a direct comparison

`slh-dsa-hw`'s `hw-sha` feature isn't a crate default; `nano-signer/Cargo.toml` requests it explicitly. To build against the fork with hardware disabled (same fork, same toolchain, isolating just the hardware-vs-software difference), drop `features = ["hw-sha"]` from that line, then build/flash/run `t` as normal.

### 3.4 Note on `Cargo.lock`

`nano-signer/Cargo.lock` and `slh-dsa-hw`'s were both left for Cargo to regenerate on the next real build after `Cargo.toml` changes; this isn't a manual step unless building with `--locked`/`--frozen`.

---

## 4. Issues encountered along the way

In roughly chronological order:

1. **FIPS 205 PDF text extraction completely failed.** The initial approach to find SLH-DSA's exact byte-size/call-count breakdown was to read the NIST FIPS 205 PDF directly. Both a WebFetch attempt and a manual Python (`zlib` + regex over PDF `Tj`/`TJ` text-drawing operators) extraction attempt failed; the PDF's font uses a CID/glyph-index encoding rather than direct ASCII text runs, so byte-level parsing without the font's ToUnicode CMap produced only whitespace. There was no `poppler-utils`/`pdftoppm` available either (`apt-get install` failed with a permission error, confirming no package-manager access in this sandbox). **Fix:** pivoted, at the user's explicit suggestion, to reading the actual RustCrypto `slh-dsa` crate source directly instead of the spec PDF. This turned out to be strictly better for this purpose: it's literally the code that runs, not a description of what code should do.

2. **No reliable way to fetch exact crate source versions via web tools.** Needed the *exact* source of `slh-dsa 0.2.0-rc.5` (a pre-release version, not always well-indexed by doc/search tools) and later `esp-hal 1.1.2`, `critical-section 1.2.0`. **Fix:** created disposable, host-target scratch Cargo projects (in the session scratchpad, not this repo) declaring the exact dependency, ran `cargo build`/`cargo fetch`, and read the result directly out of `~/.cargo/registry/src/index.crates.io-.../<crate>-<version>/`. This is now the established technique in this project for "what does this dependency actually do" questions; it's more reliable than web search or trusting training-data memory of a crate's API, especially for pre-release versions.

3. **A materially wrong assumption carried over from `slh-dsa 0.1.0` to `0.2.0-rc.5`.** Early research (and `TODO.md`'s Phase 6 notes) was based on reading `slh-dsa 0.1.0`'s source, including a note that the software implementation "recomputes that first [pk_seed-prefix] block from scratch each time rather than caching the midstate." `nano-signer` actually depends on `0.2.0-rc.5`, which already caches that midstate (`cached_hasher`/`cached_hasher_256`/`cached_hasher_512` fields, populated once via `new_from_pk_seed`, cloned per call). **Fix:** corrected in `TODO.md` Phase 6. An initial revision of this implementation also tried to replicate that same caching approach in hardware via the peripheral's save/restore support; that turned out not to compile for unrelated reasons (see item 11), so the hardware path ended up re-hashing the prefix per call after all, just still on hardware rather than software. Generalizable lesson: crate behavior claims should be checked against the exact dependency version in use, not "the crate" in the abstract, especially pre-1.0 crates that can change materially between minor/rc versions.

4. **`sha2`/`digest` version mismatch silently broke a "same implementation" claim.** Earlier benchmarking work added `sha2 = "0.10"` / `digest = "0.10"` directly to `nano-signer/Cargo.toml`, on the assumption this would unify with whatever `slh-dsa` used internally. Checking `nano-signer/Cargo.lock` directly showed this was false: `slh-dsa 0.2.0-rc.5` actually depends on `sha2 0.11.0`/`digest 0.11.3`, and Cargo had resolved *two separate copies* rather than unifying them. **Fix:** bumped `nano-signer/Cargo.toml`'s `sha2` dependency to `"0.11"` and removed the direct `digest` dependency entirely, since `main.rs` no longer names `digest::` paths directly (see item 6).

5. **A previously wrong hedge about hardware performance.** Before real numbers existed, the expectation was that hardware might be a wash or even lose at SLH-DSA's small (under-200-byte) per-call input sizes, due to fixed hardware setup overhead per call. Real measured data (the `'1'`/`'2'` raw-hashing benchmark, confirmed run in `release` profile) showed hardware ~7-8x faster even at these sizes. This was wrong, and corrected in `TODO.md`.

6. **Two independent SHA-peripheral handles would have conflicted.** `main.rs` already had its own `Sha::new(peripherals.SHA)` for the raw-hashing benchmark commands, acquired directly in `main()`. Once the hardware-backed `HashSuite` needed its own access to the same physical peripheral (via `slh_dsa::init_hw_sha`), there was no way for both to hold a handle: `peripherals.SHA` can only be moved once. **Fix:** consolidated onto a single access path. `main()` calls `slh_dsa::init_hw_sha(Sha::new(peripherals.SHA))` once at boot, and the raw-hashing benchmark commands call `slh_dsa::hw_sha256()`/`hw_sha512()`/`hw_hmac512()` convenience functions that go through the same internal singleton, instead of holding a separate `Sha` instance in `main.rs`.

7. **Whether the hardware peripheral supports the state save/restore needed to replicate midstate caching was investigated, looked resolved from source-reading alone, and then turned out not to work.** Reading `esp-hal 1.1.2`'s actual `sha.rs` source found `esp_hal::sha::Context<A>` plus `ShaDigest::save`/`restore`, which looked like exactly the needed mechanism, so an earlier revision of this implementation used it. It doesn't actually work: see item 11. The version described in section 2 above and actually shipped is the rehash-from-scratch fallback after all, discovered to be necessary only once a real compiler was involved.

8. **Whether `Sha<'d>`'s lifetime parameter could be made `'static` for storage in a global static was an open question, and resolved favorably.** Checking `esp-hal`'s `peripherals/mod.rs` (the macro-generated `Peripherals` struct) showed that `esp_hal::init()` returns `Peripherals` with every field typed as `<Name><'static>`, so `peripherals.SHA` is concretely `SHA<'static>`, with no unsafe lifetime extension needed. The static in `hw.rs` relies on exactly this.

9. **A test invocation of the vendored fork's default features failed, for an unrelated reason to this work.** `cargo build --no-default-features --features alloc` failed with several `der`/`pkcs8` compile errors. The upstream crate's real default is `["alloc", "pkcs8/alloc"]` together; enabling `alloc` alone leaves `signing_key.rs`/`verifying_key.rs`'s PKCS8 DER encoding code referencing types `pkcs8`/`der` only expose when *their* `alloc` feature is also on. Pre-existing upstream characteristic, not introduced by this fork; `nano-signer` itself was never affected, since it builds with neither feature.

10. **The `hw-sha` feature cannot be compiled in this sandbox** (no `xtensa-esp32s3-none-elf` toolchain), so the original design was checked against real source rather than a real compiler. That gap showed up almost immediately: see item 11.

11. **The `Context`-based midstate caching design didn't compile on the first real build, confirmed on real hardware.** It failed with `E0277`/`E0599` errors: `the trait bound esp_hal::sha::Sha256: Clone is not satisfied`, and similarly for `Debug` and `Sha512`. Cause: `esp_hal::sha::Context<A>` is declared `#[derive(Debug, Clone)]`. Rust's derive macros add a bound on the *type parameter itself* (`A: Clone`, `A: Debug`) rather than analyzing whether the actual fields need it; `Context<A>`'s only use of `A` is `PhantomData<A>`, which doesn't need `A: Clone`, but the derive macro adds the bound anyway. esp-hal's `Sha256`/`Sha512` marker types are plain unit structs with no `Clone`/`Debug` impl, so `Context<Sha256>: Clone` can never be satisfied for any algorithm. Reading the source correctly identified that `save`/`restore`/`Context` exist and do what their names suggest; it did not catch that the specific intended use (`.clone()` a saved `Context` before each `restore()`) is structurally impossible given how `Context` derives its traits. **Fix:** rewrote `HwPrefix256`/`HwPrefix512` to drop `Context`/`save`/`restore` entirely (section 2). Lesson: reading source correctly answers "does this API exist," but derive-macro bound behavior and other compiler-enforced constraints aren't visible from a type's own definition in isolation; that's the kind of thing only a real compiler catches.

12. **A lifetime bug in the first draft of `hw_hmac_sha256`/`hw_hmac_sha512`, caught by review rather than by a real compile this time.** The first version tried `hw_hash256(core::iter::once(ipad.as_slice()).chain(parts))`, mirroring how other call sites in `sha2.rs` chain several parts together. The difference: at those call sites every piece being chained is a parameter of the *same* function, so the compiler can infer a short, mutually-compatible lifetime. Inside `hw_hmac_sha256<'a>`'s own body, `parts: impl IntoIterator<Item = &'a [u8]>` carries `'a` as a generic parameter of that function itself, rigid and possibly `'static` from the function's point of view, while `ipad` is a local stack array. `.chain()` requires both sides to share one `Item` type, which would require the borrow checker to prove a local array outlives an arbitrary external lifetime, which it can't. **Fix:** feed `ipad` and `parts` to the hasher as two separate steps, matching the pattern `HwPrefix256::hash` already used correctly. Confirmed correct by a real build afterward (item 13).

13. **The full `hw-sha` build compiled successfully on the real target, with no further compiler-caught issues beyond items 11 and 12.** `t` ran to completion on real hardware for `128s`, `128f`, and `192f` (results in `BENCHMARKING.md`). First real confirmation that the fixes for items 11 and 12 were correct, and that the newer `Sha2L1`/`h_msg`/`prf_msg` hardware code had no further issues of the same kind. Does not confirm `192s`/`256s`/`256f`, which use the same code paths generically but haven't been built or run themselves.

14. **Getting a large signature off the device by hand surfaced two more real, practical issues**, both during the first cross-verification attempt (section 3.1). First: copying the ~70,000-character hex line directly out of a live terminal window silently truncated it, caught only by noticing the resulting file's byte count didn't match either a complete hex dump or a decoded binary signature. **Fix:** capture the whole serial session to a file with `script` instead. Second: the resulting (correctly-sized) file was still ASCII hex *text*, not decoded binary; `cli` reads raw bytes directly and has no awareness a file might be hex-encoded, so it rejected it with a generic `invalid signature` error indistinguishable from an actual cryptographic failure. **Fix:** `xxd -r -p` to decode before verifying. Both fixes are folded into section 3.1's steps as explicit byte-count checks.

---

## 5. What's left

- `192s`, `256s`, and `256f` haven't been built, benchmarked, or cross-verified. They use the same generic hardware code as the three tested parameter sets, so there's no specific reason to expect a problem, but "no specific reason to expect a problem" is exactly the confidence item 11 had right before it didn't compile.
- Why software SHA-512 was anomalously slow: investigated in depth; see `SHA512.md`.
- Phase 7 (SD card) still doesn't exist. An SD card would replace the manual capture-hex-decode dance in section 3.1 with the device just writing `message.txt.sig` directly, both the actual intended production workflow and a much less error-prone verification path.
- Upstreaming a pluggable-hash-backend design to RustCrypto's `slh-dsa`: not attempted, since the fork is scoped narrowly (one hash suite, one chip) and a generic backend acceptable to upstream would be a substantially larger effort on its own.
