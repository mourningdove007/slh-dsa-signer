// TODO(tarcieri): fix `hybrid-array` deprecation warnings
#![allow(deprecated)]

// Modified from upstream; see ../../README.md.

use core::fmt::Debug;

use crate::hashes::HashSuite;
use crate::{
    ParameterSet, address::Address, fors::ForsParams, hypertree::HypertreeParams, wots::WotsParams,
    xmss::XmssParams,
};
use crate::{PkSeed, SkPrf, SkSeed};
use const_oid::db::fips205;
use digest::Digest;
#[cfg(not(feature = "hw-sha"))]
use digest::{KeyInit, Mac};
#[cfg(not(feature = "hw-sha"))]
use hmac::Hmac;
use hybrid_array::{Array, ArraySize};
use sha2::{Sha256, Sha512};
use typenum::{Diff, Sum, U, U16, U24, U30, U32, U34, U39, U42, U47, U49, U64, U128};

/// Implementation of the MGF1 XOF
fn mgf1<H: Digest, L: ArraySize>(seed: &[u8]) -> Array<u8, L> {
    let mut result = Array::<u8, L>::default();
    result
        .chunks_mut(<H as Digest>::output_size())
        .enumerate()
        .for_each(|(counter, chunk)| {
            let counter: u32 = counter
                .try_into()
                .expect("L should be less than (2^32 * Digest::output_size) bytes");
            let mut hasher = H::new();
            hasher.update(seed);
            hasher.update(counter.to_be_bytes());
            let result = hasher.finalize();
            chunk.copy_from_slice(&result[..chunk.len()]);
        });
    result
}

/// Implementation of the component hash functions using SHA2 at Security Category 1
///
/// Follows section 11.2 of FIPS-205
#[cfg(not(feature = "hw-sha"))]
#[derive(Debug, Clone)]
pub struct Sha2L1<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
    cached_hasher: Sha256,
}

#[cfg(not(feature = "hw-sha"))]
impl<N: ArraySize, M: ArraySize> HashSuite for Sha2L1<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U32>,
    Sum<Sum<N, N>, U32>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    N: Debug + PartialEq + Eq,
    M: Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn new_from_pk_seed(pk_seed: &PkSeed<Self::N>) -> Self {
        Self {
            _n: core::marker::PhantomData,
            _m: core::marker::PhantomData,
            cached_hasher: Sha256::new_with_prefix(pk_seed.as_ref())
                // Pad with zeroes, according to section 11.2.1 of FIPS-205.
                .chain_update(Array::<u8, Diff<U64, N>>::default()),
        }
    }

    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::N> {
        let mut mac = Hmac::<Sha256>::new_from_slice(sk_prf.as_ref()).unwrap();
        mac.update(opt_rand.as_slice());
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| mac.update(msg_part.as_ref()));
        let result = mac.finalize().into_bytes();
        Array::clone_from_slice(&result[..Self::N::USIZE])
    }

    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        let mut h = Sha256::new();
        h.update(rand);
        h.update(pk_seed);
        h.update(pk_root);
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| h.update(msg_part.as_ref()));
        let result = Array(h.finalize().into());
        let seed = rand.clone().concat(pk_seed.0.clone()).concat(result);
        mgf1::<Sha256, Self::M>(&seed)
    }

    fn prf_sk(&self, sk_seed: &SkSeed<Self::N>, adrs: &impl Address) -> Array<u8, Self::N> {
        let hash = self
            .cached_hasher
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(sk_seed)
            .finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn t<L: ArraySize>(
        &self,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let mut hasher = self.cached_hasher.clone().chain_update(adrs.compressed());
        m.iter().for_each(|x| hasher.update(x.as_slice()));
        let hash = hasher.finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn h(
        &self,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let hash = self
            .cached_hasher
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(m1)
            .chain_update(m2)
            .finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn f(&self, adrs: &impl Address, m: &Array<u8, Self::N>) -> Array<u8, Self::N> {
        let hash = self
            .cached_hasher
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(m)
            .finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }
}

/// Hardware-backed `Sha2L1` (128s/128f). Requires [`crate::init_hw_sha`] to have been called once
/// at boot, or every method here panics. See `../../README.md`.
#[cfg(feature = "hw-sha")]
#[derive(Debug, Clone)]
pub struct Sha2L1<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
    hw_prefix: super::hw::HwPrefix256,
}

#[cfg(feature = "hw-sha")]
impl<N: ArraySize, M: ArraySize> HashSuite for Sha2L1<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U32>,
    Sum<Sum<N, N>, U32>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    N: Debug + PartialEq + Eq,
    M: Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn new_from_pk_seed(pk_seed: &PkSeed<Self::N>) -> Self {
        // Zero-padded per FIPS-205 section 11.2.1.
        let padding = Array::<u8, Diff<U64, N>>::default();
        Self {
            _n: core::marker::PhantomData,
            _m: core::marker::PhantomData,
            hw_prefix: super::hw::HwPrefix256::new(pk_seed.as_ref(), padding.as_slice()),
        }
    }

    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::N> {
        let result = super::hw::hw_hmac_sha256(
            sk_prf.as_ref(),
            core::iter::once(opt_rand.as_slice())
                .chain(msg.iter().copied().flatten().map(|part| part.as_ref())),
        );
        Array::clone_from_slice(&result[..Self::N::USIZE])
    }

    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        let result_bytes = super::hw::hw_hash256(
            [rand.as_slice(), pk_seed.as_ref(), pk_root.as_slice()]
                .into_iter()
                .chain(msg.iter().copied().flatten().map(|part| part.as_ref())),
        );
        let result: Array<u8, U32> = result_bytes.into();
        let seed = rand.clone().concat(pk_seed.0.clone()).concat(result);
        mgf1::<Sha256, Self::M>(&seed)
    }

    fn prf_sk(&self, sk_seed: &SkSeed<Self::N>, adrs: &impl Address) -> Array<u8, Self::N> {
        let adrs_bytes = adrs.compressed();
        let hash = self.hw_prefix.hash([adrs_bytes.as_slice(), sk_seed.as_ref()]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn t<L: ArraySize>(
        &self,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let adrs_bytes = adrs.compressed();
        let hash = self.hw_prefix.hash(
            core::iter::once(adrs_bytes.as_slice()).chain(m.iter().map(|x| x.as_slice())),
        );
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn h(
        &self,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let adrs_bytes = adrs.compressed();
        let hash = self
            .hw_prefix
            .hash([adrs_bytes.as_slice(), m1.as_slice(), m2.as_slice()]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn f(&self, adrs: &impl Address, m: &Array<u8, Self::N>) -> Array<u8, Self::N> {
        let adrs_bytes = adrs.compressed();
        let hash = self.hw_prefix.hash([adrs_bytes.as_slice(), m.as_slice()]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }
}

/// SHA2 at L1 security with small signatures
pub type Sha2_128s = Sha2L1<U16, U30>;
impl WotsParams for Sha2_128s {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Sha2_128s {
    type HPrime = U<9>;
}
impl HypertreeParams for Sha2_128s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Sha2_128s {
    type K = U<14>;
    type A = U<12>;
    type MD = U<{ (12 * 14usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_128s {
    const NAME: &'static str = "SLH-DSA-SHA2-128s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_128_S;
}

/// SHA2 at L1 security with fast signatures
pub type Sha2_128f = Sha2L1<U16, U34>;
impl WotsParams for Sha2_128f {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Sha2_128f {
    type HPrime = U<3>;
}
impl HypertreeParams for Sha2_128f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Sha2_128f {
    type K = U<33>;
    type A = U<6>;
    type MD = U<25>;
}
impl ParameterSet for Sha2_128f {
    const NAME: &'static str = "SLH-DSA-SHA2-128f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_128_F;
}

/// Implementation of the component hash functions using SHA2 at Security Category 3 and 5
///
/// Follows section 10.2 of FIPS-205
#[cfg(not(feature = "hw-sha"))]
#[derive(Debug, Clone)]
pub struct Sha2L35<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
    cached_hasher_256: Sha256,
    cached_hasher_512: Sha512,
}

#[cfg(not(feature = "hw-sha"))]
impl<N: ArraySize, M: ArraySize> HashSuite for Sha2L35<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U64>,
    Sum<Sum<N, N>, U64>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    U128: core::ops::Sub<N>,
    Diff<U128, N>: ArraySize,
    N: core::fmt::Debug + PartialEq + Eq,
    M: core::fmt::Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn new_from_pk_seed(pk_seed: &PkSeed<Self::N>) -> Self {
        Self {
            _n: core::marker::PhantomData,
            _m: core::marker::PhantomData,
            cached_hasher_256: Sha256::new_with_prefix(pk_seed.as_ref())
                // Pad with zeroes, according to section 11.2.1 of FIPS-205.
                .chain_update(Array::<u8, Diff<U64, N>>::default()),
            cached_hasher_512: Sha512::new_with_prefix(pk_seed.as_ref())
                // Pad with zeroes, according to section 11.2.1 of FIPS-205.
                .chain_update(Array::<u8, Diff<U128, N>>::default()),
        }
    }

    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::N> {
        let mut mac = Hmac::<Sha512>::new_from_slice(sk_prf.as_ref()).unwrap();
        mac.update(opt_rand.as_slice());
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| mac.update(msg_part.as_ref()));
        let result = mac.finalize().into_bytes();
        Array::clone_from_slice(&result[..Self::N::USIZE])
    }

    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        let mut h = Sha512::new();
        h.update(rand);
        h.update(pk_seed);
        h.update(pk_root);
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| h.update(msg_part.as_ref()));
        let result = Array(h.finalize().into());
        let seed = rand.clone().concat(pk_seed.0.clone()).concat(result);
        mgf1::<Sha512, Self::M>(&seed)
    }

    fn prf_sk(&self, sk_seed: &SkSeed<Self::N>, adrs: &impl Address) -> Array<u8, Self::N> {
        let hash = self
            .cached_hasher_256
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(sk_seed)
            .finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn t<L: ArraySize>(
        &self,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let mut hasher = self
            .cached_hasher_512
            .clone()
            .chain_update(adrs.compressed());
        m.iter().for_each(|x| hasher.update(x.as_slice()));
        let hash = hasher.finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn h(
        &self,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let hash = self
            .cached_hasher_512
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(m1)
            .chain_update(m2)
            .finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn f(&self, adrs: &impl Address, m: &Array<u8, Self::N>) -> Array<u8, Self::N> {
        let hash = self
            .cached_hasher_256
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(m)
            .finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }
}

/// Hardware-backed `Sha2L35` (192s/192f/256s/256f). Requires [`crate::init_hw_sha`] to have been
/// called once at boot, or every method here panics. See `../../README.md`.
#[cfg(feature = "hw-sha")]
#[derive(Debug, Clone)]
pub struct Sha2L35<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
    hw_prefix_256: super::hw::HwPrefix256,
    hw_prefix_512: super::hw::HwPrefix512,
}

#[cfg(feature = "hw-sha")]
impl<N: ArraySize, M: ArraySize> HashSuite for Sha2L35<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U64>,
    Sum<Sum<N, N>, U64>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    U128: core::ops::Sub<N>,
    Diff<U128, N>: ArraySize,
    N: core::fmt::Debug + PartialEq + Eq,
    M: core::fmt::Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn new_from_pk_seed(pk_seed: &PkSeed<Self::N>) -> Self {
        // Zero-padded per FIPS-205 section 11.2.1.
        let padding_256 = Array::<u8, Diff<U64, N>>::default();
        let padding_512 = Array::<u8, Diff<U128, N>>::default();
        Self {
            _n: core::marker::PhantomData,
            _m: core::marker::PhantomData,
            hw_prefix_256: super::hw::HwPrefix256::new(pk_seed.as_ref(), padding_256.as_slice()),
            hw_prefix_512: super::hw::HwPrefix512::new(pk_seed.as_ref(), padding_512.as_slice()),
        }
    }

    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::N> {
        let result = super::hw::hw_hmac_sha512(
            sk_prf.as_ref(),
            core::iter::once(opt_rand.as_slice())
                .chain(msg.iter().copied().flatten().map(|part| part.as_ref())),
        );
        Array::clone_from_slice(&result[..Self::N::USIZE])
    }

    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        let result_bytes = super::hw::hw_hash512(
            [rand.as_slice(), pk_seed.as_ref(), pk_root.as_slice()]
                .into_iter()
                .chain(msg.iter().copied().flatten().map(|part| part.as_ref())),
        );
        let result: Array<u8, U64> = result_bytes.into();
        let seed = rand.clone().concat(pk_seed.0.clone()).concat(result);
        mgf1::<Sha512, Self::M>(&seed)
    }

    fn prf_sk(&self, sk_seed: &SkSeed<Self::N>, adrs: &impl Address) -> Array<u8, Self::N> {
        let adrs_bytes = adrs.compressed();
        let hash = self
            .hw_prefix_256
            .hash([adrs_bytes.as_slice(), sk_seed.as_ref()]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn t<L: ArraySize>(
        &self,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let adrs_bytes = adrs.compressed();
        let hash = self.hw_prefix_512.hash(
            core::iter::once(adrs_bytes.as_slice()).chain(m.iter().map(|x| x.as_slice())),
        );
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn h(
        &self,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let adrs_bytes = adrs.compressed();
        let hash = self
            .hw_prefix_512
            .hash([adrs_bytes.as_slice(), m1.as_slice(), m2.as_slice()]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    fn f(&self, adrs: &impl Address, m: &Array<u8, Self::N>) -> Array<u8, Self::N> {
        let adrs_bytes = adrs.compressed();
        let hash = self
            .hw_prefix_256
            .hash([adrs_bytes.as_slice(), m.as_slice()]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }
}

/// SHA2 at L3 security with small signatures
pub type Sha2_192s = Sha2L35<U24, U39>;
impl WotsParams for Sha2_192s {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Sha2_192s {
    type HPrime = U<9>;
}
impl HypertreeParams for Sha2_192s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Sha2_192s {
    type K = U<17>;
    type A = U<14>;
    type MD = U<{ (14 * 17usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_192s {
    const NAME: &'static str = "SLH-DSA-SHA2-192s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_192_S;
}

/// SHA2 at L3 security with fast signatures
pub type Sha2_192f = Sha2L35<U24, U42>;
impl WotsParams for Sha2_192f {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Sha2_192f {
    type HPrime = U<3>;
}
impl HypertreeParams for Sha2_192f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Sha2_192f {
    type K = U<33>;
    type A = U<8>;
    type MD = U<{ (33 * 8usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_192f {
    const NAME: &'static str = "SLH-DSA-SHA2-192f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_192_F;
}

/// SHA2 at L5 security with small signatures
pub type Sha2_256s = Sha2L35<U32, U47>;
impl WotsParams for Sha2_256s {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Sha2_256s {
    type HPrime = U<8>;
}
impl HypertreeParams for Sha2_256s {
    type D = U<8>;
    type H = U<64>;
}
impl ForsParams for Sha2_256s {
    type K = U<22>;
    type A = U<14>;
    type MD = U<{ (14 * 22usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_256s {
    const NAME: &'static str = "SLH-DSA-SHA2-256s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_256_S;
}

/// SHA2 at L5 security with fast signatures
pub type Sha2_256f = Sha2L35<U32, U49>;
impl WotsParams for Sha2_256f {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Sha2_256f {
    type HPrime = U<4>;
}
impl HypertreeParams for Sha2_256f {
    type D = U<17>;
    type H = U<68>;
}
impl ForsParams for Sha2_256f {
    type K = U<35>;
    type A = U<9>;
    type MD = U<{ (35 * 9usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_256f {
    const NAME: &'static str = "SLH-DSA-SHA2-256f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_256_F;
}
