//! Hardware SHA-256/SHA-512 backend for `Sha2L1`/`Sha2L35`, via `esp_hal::sha`.
//!
//! See `../../README.md` for the singleton-peripheral design, the `Context::Clone` dead end this
//! module doesn't use, and why prefixes are re-hashed per call instead of cached as peripheral
//! state.

use esp_hal::sha::{Sha, Sha256 as HwSha256, Sha512 as HwSha512, ShaDigest};

static HW_SHA: critical_section::Mutex<core::cell::RefCell<Option<Sha<'static>>>> =
    critical_section::Mutex::new(core::cell::RefCell::new(None));

/// Gives the hash suite ownership of the ESP32-S3 SHA peripheral. Call this
/// once at boot, before constructing any `SigningKey`/`VerifyingKey`, or
/// signing/verifying will panic.
pub fn init_hw_sha(sha: Sha<'static>) {
    critical_section::with(|cs| {
        *HW_SHA.borrow_ref_mut(cs) = Some(sha);
    });
}

fn with_hw_sha<R>(f: impl FnOnce(&mut Sha<'static>) -> R) -> R {
    critical_section::with(|cs| {
        let mut slot = HW_SHA.borrow_ref_mut(cs);
        let sha = slot.as_mut().expect(
            "slh_dsa hw-sha: hardware SHA peripheral not initialized -- call \
             slh_dsa::init_hw_sha() once at boot before signing or verifying",
        );
        f(sha)
    })
}

/// Feeds `data` to `hasher` in full, looping past the peripheral's
/// `WouldBlock` backpressure. Mirrors the blocking pattern from esp-hal's own
/// `Sha` driver documentation.
fn hw_update_all<A: esp_hal::sha::ShaAlgorithm>(
    hasher: &mut ShaDigest<'static, A, &mut Sha<'static>>,
    mut data: &[u8],
) {
    while !data.is_empty() {
        data = nb::block!(hasher.update(data)).unwrap();
    }
}

/// One-shot hardware SHA-256 over a single buffer. Public so external benchmarking code can share
/// the same peripheral singleton; see `../../README.md`.
pub fn hw_sha256(data: &[u8]) -> [u8; 32] {
    hw_hash256(core::iter::once(data))
}

/// One-shot hardware SHA-256 over `parts`, with no cached prefix.
pub(crate) fn hw_hash256<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut out = [0u8; 32];
    with_hw_sha(|sha| {
        let mut hasher = ShaDigest::<HwSha256, _>::new(sha);
        for part in parts {
            hw_update_all(&mut hasher, part);
        }
        nb::block!(hasher.finish(&mut out)).unwrap();
    });
    out
}

/// Same as [`hw_hash256`], for SHA-512.
pub(crate) fn hw_hash512<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
    let mut out = [0u8; 64];
    with_hw_sha(|sha| {
        let mut hasher = ShaDigest::<HwSha512, _>::new(sha);
        for part in parts {
            hw_update_all(&mut hasher, part);
        }
        nb::block!(hasher.finish(&mut out)).unwrap();
    });
    out
}

/// Hand-rolled HMAC-SHA-256 around [`hw_hash256`]. `key` must be at most 64 bytes (the SHA-256
/// block size); see `../../README.md`.
pub(crate) fn hw_hmac_sha256<'a>(key: &[u8], parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    // Two separate feed steps, not `.chain()`: see README.md's lifetime note.
    let mut inner_out = [0u8; 32];
    with_hw_sha(|sha| {
        let mut hasher = ShaDigest::<HwSha256, _>::new(sha);
        hw_update_all(&mut hasher, &ipad);
        for part in parts {
            hw_update_all(&mut hasher, part);
        }
        nb::block!(hasher.finish(&mut inner_out)).unwrap();
    });
    hw_hash256([opad.as_slice(), inner_out.as_slice()])
}

/// Same as [`hw_hmac_sha256`], for HMAC-SHA-512 (128-byte block size).
pub(crate) fn hw_hmac_sha512<'a>(key: &[u8], parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
    const BLOCK: usize = 128;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    // Two separate feed steps, not `.chain()`: see `hw_hmac_sha256` and README.md.
    let mut inner_out = [0u8; 64];
    with_hw_sha(|sha| {
        let mut hasher = ShaDigest::<HwSha512, _>::new(sha);
        hw_update_all(&mut hasher, &ipad);
        for part in parts {
            hw_update_all(&mut hasher, part);
        }
        nb::block!(hasher.finish(&mut inner_out)).unwrap();
    });
    hw_hash512([opad.as_slice(), inner_out.as_slice()])
}

/// One-block `pk_seed || zero-padding` prefix, re-hashed per call (always exactly 64 bytes; see
/// `../../README.md`).
#[derive(Clone, Debug)]
pub(crate) struct HwPrefix256 {
    block: [u8; 64],
}

impl HwPrefix256 {
    pub(crate) fn new(pk_seed: &[u8], zero_padding: &[u8]) -> Self {
        let mut block = [0u8; 64];
        let (seed_part, pad_part) = block.split_at_mut(pk_seed.len());
        seed_part.copy_from_slice(pk_seed);
        pad_part[..zero_padding.len()].copy_from_slice(zero_padding);
        Self { block }
    }

    /// Hashes the prefix followed by `parts`, returning the full 32-byte digest.
    pub(crate) fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
        let mut out = [0u8; 32];
        with_hw_sha(|sha| {
            let mut hasher = ShaDigest::<HwSha256, _>::new(sha);
            hw_update_all(&mut hasher, &self.block);
            for part in parts {
                hw_update_all(&mut hasher, part);
            }
            nb::block!(hasher.finish(&mut out)).unwrap();
        });
        out
    }
}

/// Same as [`HwPrefix256`], for SHA-512. Always exactly 128 bytes (one
/// SHA-512 block).
#[derive(Clone, Debug)]
pub(crate) struct HwPrefix512 {
    block: [u8; 128],
}

impl HwPrefix512 {
    pub(crate) fn new(pk_seed: &[u8], zero_padding: &[u8]) -> Self {
        let mut block = [0u8; 128];
        let (seed_part, pad_part) = block.split_at_mut(pk_seed.len());
        seed_part.copy_from_slice(pk_seed);
        pad_part[..zero_padding.len()].copy_from_slice(zero_padding);
        Self { block }
    }

    pub(crate) fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
        let mut out = [0u8; 64];
        with_hw_sha(|sha| {
            let mut hasher = ShaDigest::<HwSha512, _>::new(sha);
            hw_update_all(&mut hasher, &self.block);
            for part in parts {
                hw_update_all(&mut hasher, part);
            }
            nb::block!(hasher.finish(&mut out)).unwrap();
        });
        out
    }
}
