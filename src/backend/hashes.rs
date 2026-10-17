//! Independent MIT fixed-message parallel hashes, using FIPS 180-4 and RIPEMD-160.
//! Round constants/schedules: RustCrypto sha2 0.10.9 and ripemd 0.1.3 (MIT option).
//! No VanitySearch/DankMiner implementation is used here.
#[cfg(any(test, feature = "developer-tools"))]
use sha2::{Digest, Sha512};
pub fn hash160_many(input: &[[u8; 33]], out: &mut [[u8; 20]], simd: bool) {
    assert_eq!(input.len(), out.len());
    let mut i = 0;
    #[cfg(target_arch = "x86_64")]
    if simd {
        if std::is_x86_feature_detected!("avx2") {
            while i + 8 <= input.len() {
                // SAFETY: AVX2 is checked immediately before dispatch.
                unsafe {
                    x86::hash160x8(&input[i..i + 8], &mut out[i..i + 8]);
                }
                i += 8;
            }
        }
        while i + 4 <= input.len() {
            x86::hash160::<x86::U32x4>(&input[i..i + 4], &mut out[i..i + 4]);
            i += 4;
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = simd;
    for j in i..input.len() {
        out[j] = crate::chains::hash160(&input[j]);
    }
}
pub fn keccak_many(input: &[[u8; 64]], out: &mut [[u8; 20]], simd: bool) {
    assert_eq!(input.len(), out.len());
    let mut i = 0;
    #[cfg(target_arch = "x86_64")]
    if simd && std::is_x86_feature_detected!("avx2") {
        while i + 4 <= input.len() {
            // SAFETY: AVX2 is checked immediately before dispatch.
            unsafe {
                x86::keccak(&input[i..i + 4], &mut out[i..i + 4]);
            }
            i += 4;
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = simd;
    for j in i..input.len() {
        out[j].copy_from_slice(&crate::crypto::keccak(&input[j])[12..]);
    }
}
#[cfg(any(test, feature = "developer-tools"))]
pub(crate) fn sha512_many(input: &[[u8; 32]], out: &mut [[u8; 64]], simd: bool) {
    assert_eq!(input.len(), out.len());
    let mut i = 0;
    #[cfg(target_arch = "x86_64")]
    if simd && std::is_x86_feature_detected!("avx2") {
        while i + 4 <= input.len() {
            // SAFETY: AVX2 is checked immediately before dispatch.
            unsafe {
                x86::sha512(&input[i..i + 4], &mut out[i..i + 4]);
            }
            i += 4;
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = simd;
    for j in i..input.len() {
        use zeroize::Zeroize;
        let mut digest = Sha512::digest(input[j]);
        out[j].copy_from_slice(&digest);
        digest[..].zeroize();
    }
}
#[cfg(target_arch = "x86_64")]
mod x86 {
    use std::arch::x86_64::*;
    use std::ops::{Add, BitAnd, BitOr, BitXor, Not};
    #[cfg(any(test, feature = "developer-tools"))]
    use zeroize::{Zeroize, Zeroizing};
    pub(super) trait W32:
        Copy
        + Add<Output = Self>
        + BitXor<Output = Self>
        + BitAnd<Output = Self>
        + BitOr<Output = Self>
        + Not<Output = Self>
    {
        const LANES: usize;
        fn splat(n: u32) -> Self;
        fn load(n: [u32; 8]) -> Self;
        fn store(self) -> [u32; 8];
        fn left(self, n: u32) -> Self;
        fn right(self, n: u32) -> Self;
        #[inline(always)]
        fn rol(self, n: u32) -> Self {
            self.left(n) | self.right((32 - n) % 32)
        }
        #[inline(always)]
        fn ror(self, n: u32) -> Self {
            self.right(n) | self.left(32 - n)
        }
        #[inline(always)]
        fn swap(self) -> Self {
            let lo = Self::splat(0x00ff00ff);
            let v = ((self & lo).left(8)) | ((self.right(8)) & lo);
            v.rol(16)
        }
    }
    #[derive(Clone, Copy)]
    pub(super) struct U32x4(__m128i);
    impl Add for U32x4 {
        type Output = Self;
        #[inline(always)]
        fn add(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm_add_epi32(self.0, rhs.0)) }
        }
    }
    impl BitXor for U32x4 {
        type Output = Self;
        #[inline(always)]
        fn bitxor(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm_xor_si128(self.0, rhs.0)) }
        }
    }
    impl BitAnd for U32x4 {
        type Output = Self;
        #[inline(always)]
        fn bitand(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm_and_si128(self.0, rhs.0)) }
        }
    }
    impl BitOr for U32x4 {
        type Output = Self;
        #[inline(always)]
        fn bitor(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm_or_si128(self.0, rhs.0)) }
        }
    }
    impl Not for U32x4 {
        type Output = Self;
        #[inline(always)]
        fn not(self) -> Self {
            self ^ Self::splat(u32::MAX)
        }
    }
    impl W32 for U32x4 {
        const LANES: usize = 4;
        #[inline(always)]
        fn splat(n: u32) -> Self {
            // SAFETY: private construction is guarded by the dispatcher's feature check.
            unsafe { Self(_mm_set1_epi32(n as i32)) }
        }
        fn load(n: [u32; 8]) -> Self {
            // SAFETY: the fixed array contains at least 16 readable bytes; alignment is not required; dispatch checked ISA.
            unsafe { Self(_mm_loadu_si128(n.as_ptr().cast())) }
        }
        fn store(self) -> [u32; 8] {
            let mut out = [0; 8];
            // SAFETY: the fixed output array holds a complete vector; unaligned stores are supported; dispatch checked ISA.
            unsafe {
                _mm_storeu_si128(out.as_mut_ptr().cast(), self.0);
            }
            out
        }
        #[inline(always)]
        fn left(self, n: u32) -> Self {
            // SAFETY: vector construction requires the ISA check; shifts use a bounded public round constant.
            unsafe { Self(_mm_sll_epi32(self.0, _mm_cvtsi32_si128(n as i32))) }
        }
        #[inline(always)]
        fn right(self, n: u32) -> Self {
            // SAFETY: vector construction requires the ISA check; shifts use a bounded public round constant.
            unsafe { Self(_mm_srl_epi32(self.0, _mm_cvtsi32_si128(n as i32))) }
        }
    }
    #[derive(Clone, Copy)]
    pub(super) struct U32x8(__m256i);
    impl Add for U32x8 {
        type Output = Self;
        #[inline(always)]
        fn add(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm256_add_epi32(self.0, rhs.0)) }
        }
    }
    impl BitXor for U32x8 {
        type Output = Self;
        #[inline(always)]
        fn bitxor(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm256_xor_si256(self.0, rhs.0)) }
        }
    }
    impl BitAnd for U32x8 {
        type Output = Self;
        #[inline(always)]
        fn bitand(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm256_and_si256(self.0, rhs.0)) }
        }
    }
    impl BitOr for U32x8 {
        type Output = Self;
        #[inline(always)]
        fn bitor(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm256_or_si256(self.0, rhs.0)) }
        }
    }
    impl Not for U32x8 {
        type Output = Self;
        #[inline(always)]
        fn not(self) -> Self {
            self ^ Self::splat(u32::MAX)
        }
    }
    impl W32 for U32x8 {
        const LANES: usize = 8;
        #[inline(always)]
        fn splat(n: u32) -> Self {
            // SAFETY: private construction is guarded by the dispatcher's feature check.
            unsafe { Self(_mm256_set1_epi32(n as i32)) }
        }
        fn load(n: [u32; 8]) -> Self {
            // SAFETY: the fixed array contains at least 32 readable bytes; alignment is not required; dispatch checked ISA.
            unsafe { Self(_mm256_loadu_si256(n.as_ptr().cast())) }
        }
        fn store(self) -> [u32; 8] {
            let mut out = [0; 8];
            // SAFETY: the fixed output array holds a complete vector; unaligned stores are supported; dispatch checked ISA.
            unsafe {
                _mm256_storeu_si256(out.as_mut_ptr().cast(), self.0);
            }
            out
        }
        #[inline(always)]
        fn left(self, n: u32) -> Self {
            // SAFETY: vector construction requires the ISA check; shifts use a bounded public round constant.
            unsafe { Self(_mm256_sll_epi32(self.0, _mm_cvtsi32_si128(n as i32))) }
        }
        #[inline(always)]
        fn right(self, n: u32) -> Self {
            // SAFETY: vector construction requires the ISA check; shifts use a bounded public round constant.
            unsafe { Self(_mm256_srl_epi32(self.0, _mm_cvtsi32_si128(n as i32))) }
        }
    }
    #[derive(Clone, Copy)]
    pub(super) struct U64x4(__m256i);
    impl Add for U64x4 {
        type Output = Self;
        #[inline(always)]
        fn add(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm256_add_epi64(self.0, rhs.0)) }
        }
    }
    impl BitXor for U64x4 {
        type Output = Self;
        #[inline(always)]
        fn bitxor(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm256_xor_si256(self.0, rhs.0)) }
        }
    }
    impl BitAnd for U64x4 {
        type Output = Self;
        #[inline(always)]
        fn bitand(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm256_and_si256(self.0, rhs.0)) }
        }
    }
    impl BitOr for U64x4 {
        type Output = Self;
        #[inline(always)]
        fn bitor(self, rhs: Self) -> Self {
            // SAFETY: this private vector type is only constructed after runtime feature detection; SSE2 is baseline on x86_64.
            unsafe { Self(_mm256_or_si256(self.0, rhs.0)) }
        }
    }
    impl Not for U64x4 {
        type Output = Self;
        #[inline(always)]
        fn not(self) -> Self {
            self ^ Self::splat(u64::MAX)
        }
    }
    impl W64 for U64x4 {
        #[inline(always)]
        fn splat(n: u64) -> Self {
            // SAFETY: private construction is guarded by the dispatcher's feature check.
            unsafe { Self(_mm256_set1_epi64x(n as i64)) }
        }
        fn load(n: [u64; 4]) -> Self {
            // SAFETY: the fixed array contains at least 32 readable bytes; alignment is not required; dispatch checked ISA.
            unsafe { Self(_mm256_loadu_si256(n.as_ptr().cast())) }
        }
        fn store(self) -> [u64; 4] {
            let mut out = [0; 4];
            // SAFETY: the fixed output array holds a complete vector; unaligned stores are supported; dispatch checked ISA.
            unsafe {
                _mm256_storeu_si256(out.as_mut_ptr().cast(), self.0);
            }
            out
        }
        #[inline(always)]
        fn left(self, n: u32) -> Self {
            // SAFETY: vector construction requires the ISA check; shifts use a bounded public round constant.
            unsafe { Self(_mm256_sll_epi64(self.0, _mm_cvtsi32_si128(n as i32))) }
        }
        #[inline(always)]
        fn right(self, n: u32) -> Self {
            // SAFETY: vector construction requires the ISA check; shifts use a bounded public round constant.
            unsafe { Self(_mm256_srl_epi64(self.0, _mm_cvtsi32_si128(n as i32))) }
        }
    }
    #[cfg(any(test, feature = "developer-tools"))]
    impl Zeroize for U64x4 {
        fn zeroize(&mut self) {
            // SAFETY: self is a valid aligned live vector. A volatile zero store and fence retain buffer erasure.
            unsafe {
                std::ptr::write_volatile(self, Self::splat(0));
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
    trait W64:
        Copy
        + Add<Output = Self>
        + BitXor<Output = Self>
        + BitAnd<Output = Self>
        + BitOr<Output = Self>
        + Not<Output = Self>
    {
        fn splat(n: u64) -> Self;
        fn load(n: [u64; 4]) -> Self;
        fn store(self) -> [u64; 4];
        fn left(self, n: u32) -> Self;
        fn right(self, n: u32) -> Self;
        #[inline(always)]
        fn rol(self, n: u32) -> Self {
            if n == 0 {
                self
            } else {
                self.left(n) | self.right(64 - n)
            }
        }
        #[inline(always)]
        #[cfg(any(test, feature = "developer-tools"))]
        fn ror(self, n: u32) -> Self {
            self.right(n) | self.left(64 - n)
        }
    }
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn hash160x8(input: &[[u8; 33]], out: &mut [[u8; 20]]) {
        hash160::<U32x8>(input, out)
    }
    const K32: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    #[cfg(any(test, feature = "developer-tools"))]
    const K64: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];
    const RL: [usize; 80] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9,
        5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8,
        12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];
    const SL: [usize; 80] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12,
        15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14,
        15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11,
        8, 5, 6,
    ];
    const RR: [usize; 80] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8,
        12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11,
        15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];
    const SR: [usize; 80] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7,
        12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11,
        14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13,
        11, 11,
    ];
    #[inline(always)]
    fn rf<V: W32>(r: usize, x: V, y: V, z: V) -> V {
        match r {
            0 => x ^ y ^ z,
            1 => (x & y) | (!x & z),
            2 => (x | !y) ^ z,
            3 => (x & z) | (y & !z),
            _ => x ^ (y | !z),
        }
    }
    #[inline(always)]
    pub(super) fn hash160<V: W32>(input: &[[u8; 33]], out: &mut [[u8; 20]]) {
        let v = V::splat;
        let mut w = [v(0); 64];
        for (j, word) in w.iter_mut().enumerate().take(9) {
            let mut a = [0; 8];
            for lane in 0..V::LANES {
                let mut b = [0; 4];
                for (k, byte) in b.iter_mut().enumerate() {
                    let p = j * 4 + k;
                    *byte = if p < 33 {
                        input[lane][p]
                    } else if p == 33 {
                        128
                    } else {
                        0
                    };
                }
                a[lane] = u32::from_be_bytes(b);
            }
            *word = V::load(a);
        }
        w[15] = v(264);
        for j in 16..64 {
            let x = w[j - 15];
            let y = w[j - 2];
            w[j] = w[j - 16]
                + (x.ror(7) ^ x.ror(18) ^ x.right(3))
                + w[j - 7]
                + (y.ror(17) ^ y.ror(19) ^ y.right(10));
        }
        let iv = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut a = iv.map(v);
        for j in 0..64 {
            let t = a[7]
                + (a[4].ror(6) ^ a[4].ror(11) ^ a[4].ror(25))
                + ((a[4] & a[5]) ^ (!a[4] & a[6]))
                + v(K32[j])
                + w[j];
            let u = (a[0].ror(2) ^ a[0].ror(13) ^ a[0].ror(22))
                + ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));
            a = [t + u, a[0], a[1], a[2], a[3] + t, a[4], a[5], a[6]];
        }
        let mut x = [v(0); 16];
        for j in 0..8 {
            x[j] = (a[j] + v(iv[j])).swap();
        }
        x[8] = v(128);
        x[14] = v(256);
        let h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0].map(v);
        let mut l = h;
        let mut r = h;
        let kl = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
        let kr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
        for j in 0..80 {
            let round = j / 16;
            let t = (l[0] + rf(round, l[1], l[2], l[3]) + x[RL[j]] + v(kl[round]))
                .rol(SL[j] as u32)
                + l[4];
            l = [l[4], t, l[1], l[2].rol(10), l[3]];
            let t = (r[0] + rf(4 - round, r[1], r[2], r[3]) + x[RR[j]] + v(kr[round]))
                .rol(SR[j] as u32)
                + r[4];
            r = [r[4], t, r[1], r[2].rol(10), r[3]];
        }
        let result = [
            h[1] + l[2] + r[3],
            h[2] + l[3] + r[4],
            h[3] + l[4] + r[0],
            h[4] + l[0] + r[1],
            h[0] + l[1] + r[2],
        ];
        for (j, value) in result.iter().enumerate() {
            let words = value.store();
            for lane in 0..V::LANES {
                out[lane][j * 4..j * 4 + 4].copy_from_slice(&words[lane].to_le_bytes());
            }
        }
    }
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn keccak(input: &[[u8; 64]], out: &mut [[u8; 20]]) {
        let v = U64x4::splat;
        let mut a = [v(0); 25];
        for j in 0..8 {
            a[j] = U64x4::load(std::array::from_fn(|lane| {
                u64::from_le_bytes(input[lane][j * 8..j * 8 + 8].try_into().expect("word"))
            }));
        }
        a[8] = v(1);
        a[16] = v(0x8000000000000000);
        for constant in RC {
            let c: [U64x4; 5] =
                std::array::from_fn(|i| a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20]);
            let d: [U64x4; 5] = std::array::from_fn(|i| c[(i + 4) % 5] ^ c[(i + 1) % 5].rol(1));
            let mut b = [v(0); 25];
            for j in 0..5 {
                for i in 0..5 {
                    let k = i + 5 * j;
                    b[j + 5 * ((2 * i + 3 * j) % 5)] = (a[k] ^ d[i]).rol(ROT[k]);
                }
            }
            for j in 0..5 {
                for i in 0..5 {
                    a[i + 5 * j] =
                        b[i + 5 * j] ^ (!b[(i + 1) % 5 + 5 * j] & b[(i + 2) % 5 + 5 * j]);
                }
            }
            a[0] = a[0] ^ v(constant);
        }
        let words: [_; 4] = std::array::from_fn(|j| a[j].store());
        for lane in 0..4 {
            for (j, byte) in out[lane].iter_mut().enumerate() {
                let pos = j + 12;
                *byte = (words[pos / 8][lane] >> (8 * (pos % 8))) as u8;
            }
        }
    }
    #[cfg(any(test, feature = "developer-tools"))]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn sha512(input: &[[u8; 32]], out: &mut [[u8; 64]]) {
        let v = U64x4::splat;
        let mut w = Zeroizing::new([v(0); 80]);
        for j in 0..4 {
            let mut words = Zeroizing::new([0u64; 4]);
            for lane in 0..4 {
                words[lane] = u64::from_be_bytes(
                    input[lane][j * 8..j * 8 + 8].try_into().expect("seed word"),
                );
            }
            w[j] = U64x4::load(*words);
        }
        w[4] = v(0x8000000000000000);
        w[15] = v(256);
        for j in 16..80 {
            w[j] = w[j - 16]
                + (w[j - 15].ror(1) ^ w[j - 15].ror(8) ^ w[j - 15].right(7))
                + w[j - 7]
                + (w[j - 2].ror(19) ^ w[j - 2].ror(61) ^ w[j - 2].right(6));
        }
        let iv = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];
        let mut a = Zeroizing::new(iv.map(v));
        for j in 0..80 {
            let mut t = a[7]
                + (a[4].ror(14) ^ a[4].ror(18) ^ a[4].ror(41))
                + ((a[4] & a[5]) ^ (!a[4] & a[6]))
                + v(K64[j])
                + w[j];
            let mut u = (a[0].ror(28) ^ a[0].ror(34) ^ a[0].ror(39))
                + ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));
            *a = [t + u, a[0], a[1], a[2], a[3] + t, a[4], a[5], a[6]];
            t.zeroize();
            u.zeroize();
        }
        for j in 0..8 {
            let mut value = a[j] + v(iv[j]);
            let mut words = Zeroizing::new(value.store());
            for lane in 0..4 {
                out[lane][j * 8..j * 8 + 8].copy_from_slice(&words[lane].to_be_bytes());
            }
            words.zeroize();
            value.zeroize();
        }
    }
}

pub(crate) fn self_test() -> anyhow::Result<()> {
    static CHECK: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    let result = CHECK.get_or_init(|| {
        let a: [[u8; 33]; 13] =
            std::array::from_fn(|i| std::array::from_fn(|j| (i * 37 + j * 19) as u8));
        let b: [[u8; 64]; 13] =
            std::array::from_fn(|i| std::array::from_fn(|j| (i * 71 + j * 13) as u8));
        let mut hashes = [[0; 20]; 13];
        hash160_many(&a, &mut hashes, true);
        for i in 0..13 {
            if hashes[i] != crate::chains::hash160(&a[i]) {
                return Err("CPU parallel Hash160 self-test mismatch".into());
            }
        }
        keccak_many(&b, &mut hashes, true);
        for i in 0..13 {
            if hashes[i] != crate::crypto::keccak(&b[i])[12..] {
                return Err("CPU parallel Keccak self-test mismatch".into());
            }
        }
        Ok(())
    });
    result
        .as_ref()
        .map_err(|message| anyhow::anyhow!(message.clone()))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parallel_hashes_match_reference_with_tails() {
        for n in 0..=33 {
            let inputs: Vec<[u8; 33]> = (0..n)
                .map(|i| std::array::from_fn(|j| ((i * 71 + j * 19) % 256) as u8))
                .collect();
            let mut got = vec![[0; 20]; n];
            hash160_many(&inputs, &mut got, true);
            for i in 0..n {
                assert_eq!(got[i], crate::chains::hash160(&inputs[i]));
            }
            let inputs: Vec<[u8; 64]> = (0..n)
                .map(|i| std::array::from_fn(|j| ((i * 39 + j * 47) % 256) as u8))
                .collect();
            keccak_many(&inputs, &mut got, true);
            for i in 0..n {
                assert_eq!(got[i], crate::crypto::keccak(&inputs[i])[12..]);
            }
            let seeds: Vec<[u8; 32]> = (0..n)
                .map(|i| std::array::from_fn(|j| ((i * 53 + j * 11) % 256) as u8))
                .collect();
            let mut digests = vec![[0; 64]; n];
            sha512_many(&seeds, &mut digests, true);
            for i in 0..n {
                assert_eq!(digests[i][..], Sha512::digest(seeds[i])[..]);
            }
        }
    }
}
