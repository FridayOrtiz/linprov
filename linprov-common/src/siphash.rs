//! SipHash-2-4 — the keyed PRF that replaces FNV for hashing paths into the
//! allowlist / provenance record (finding #3).
//!
//! FNV is non-cryptographic and invertible: a local attacker can *construct*
//! a path that hashes to an allowlisted path's value and bypass enforce mode.
//! SipHash keyed with a per-install secret is a PRF — without the key, an
//! attacker can't predict or collide outputs, even with a query oracle (a
//! non-root user can read the `security.bpf.linprov.origin` xattr off a file
//! they own, so oracle-resistance is required; that's why a lightweight
//! algebraic keyed hash wouldn't do).
//!
//! Both the userspace daemon and the eBPF program must compute identical
//! values. Userspace calls the one-shot [`siphash`]. The eBPF program can't
//! (it needs a streaming walk that emits a hash at every `/` of a path in one
//! pass), so it re-implements the same construction from [`sip_init`],
//! [`sipround`], and the final block / finalization rules — the
//! `streaming_walk_matches_one_shot` test below pins that streaming form to
//! the one-shot, byte-for-byte, so the BPF port has an executable spec.

/// SipHash internal state: four 64-bit words.
pub type SipState = [u64; 4];

/// SipHash initialization vector (the ASCII of "somepseudorandomlygenerated…").
pub const SIP_IV: SipState = [
    0x736f_6d65_7073_6575,
    0x646f_7261_6e64_6f6d,
    0x6c79_6765_6e65_7261,
    0x7465_6462_7974_6573,
];

/// Compression rounds (the `2` in SipHash-2-4).
pub const SIP_C: usize = 2;
/// Finalization rounds (the `4` in SipHash-2-4).
pub const SIP_D: usize = 4;

/// Initialize the state from a 128-bit key `(k0, k1)`.
#[inline(always)]
pub fn sip_init(k0: u64, k1: u64) -> SipState {
    [
        SIP_IV[0] ^ k0,
        SIP_IV[1] ^ k1,
        SIP_IV[2] ^ k0,
        SIP_IV[3] ^ k1,
    ]
}

/// One SipRound — the shared core of both compression and finalization.
#[inline(always)]
pub fn sipround(v: &mut SipState) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// Absorb one full 8-byte message word `m` into the state (compression).
#[inline(always)]
pub fn sip_absorb(v: &mut SipState, m: u64) {
    v[3] ^= m;
    let mut i = 0;
    while i < SIP_C {
        sipround(v);
        i += 1;
    }
    v[0] ^= m;
}

/// Finalize a copy of the state for a message of total length `len` whose
/// trailing `< 8` bytes are packed (little-endian) in `tail`. Returns the
/// 64-bit hash. The state is taken by value so callers can finalize a
/// *clone* at each `/` while continuing to absorb into the original — that's
/// how the eBPF walk emits an ancestor-prefix hash without restarting.
#[inline(always)]
pub fn sip_finish(mut v: SipState, len: usize, tail: u64) -> u64 {
    let b = ((len as u64) << 56) | tail;
    v[3] ^= b;
    let mut i = 0;
    while i < SIP_C {
        sipround(&mut v);
        i += 1;
    }
    v[0] ^= b;
    v[2] ^= 0xff;
    i = 0;
    while i < SIP_D {
        sipround(&mut v);
        i += 1;
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// One-shot SipHash-2-4 of `data` under key `(k0, k1)`. Used by userspace;
/// the eBPF path walk mirrors this construction (see the agreement test).
#[cfg(feature = "user")]
pub fn siphash(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v = sip_init(k0, k1);
    let len = data.len();
    let mut i = 0;
    while i + 8 <= len {
        let m = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        sip_absorb(&mut v, m);
        i += 8;
    }
    let mut tail: u64 = 0;
    let mut shift = 0;
    while i < len {
        tail |= (data[i] as u64) << shift;
        shift += 8;
        i += 1;
    }
    sip_finish(v, len, tail)
}

#[cfg(all(test, feature = "user"))]
mod tests {
    use super::*;

    /// Test-side mirror of what the eBPF program will do: a single streaming
    /// pass over a NUL-free path that, at each `/`, finalizes a *clone* of the
    /// running state to get that prefix's hash, and tracks a separate
    /// component state (reset after each `/`) for the basename. Returns
    /// `(full, folder, basename, ancestors)`.
    fn streaming_walk(k0: u64, k1: u64, path: &[u8]) -> (u64, u64, u64, Vec<u64>) {
        let mut v = sip_init(k0, k1); // whole-path state
        let mut full_len = 0usize;
        let mut tail: u64 = 0; // pending < 8 bytes of the whole path
        let mut tail_n = 0usize;

        let mut c = sip_init(k0, k1); // current-component state
        let mut comp_len = 0usize;
        let mut comp_tail: u64 = 0;
        let mut comp_n = 0usize;

        let mut folder = 0u64;
        let mut ancestors = Vec::new();

        let absorb = |v: &mut SipState, tail: &mut u64, tn: &mut usize, len: &mut usize, b: u8| {
            *tail |= (b as u64) << (8 * *tn);
            *tn += 1;
            *len += 1;
            if *tn == 8 {
                sip_absorb(v, *tail);
                *tail = 0;
                *tn = 0;
            }
        };

        for &b in path {
            absorb(&mut v, &mut tail, &mut tail_n, &mut full_len, b);
            if b == b'/' {
                // ancestor / folder = whole-path hash up to & including this '/'
                folder = sip_finish(v, full_len, tail);
                ancestors.push(folder);
                // restart the component (basename) state after the slash
                c = sip_init(k0, k1);
                comp_tail = 0;
                comp_n = 0;
                comp_len = 0;
            } else {
                absorb(&mut c, &mut comp_tail, &mut comp_n, &mut comp_len, b);
            }
        }
        let full = sip_finish(v, full_len, tail);
        let basename = sip_finish(c, comp_len, comp_tail);
        (full, folder, basename, ancestors)
    }

    #[test]
    fn matches_published_2_4_vector() {
        // Reference vector from the SipHash paper / reference implementation:
        // key = bytes 00..0f, message = bytes 00..0e (15 bytes).
        let k0 = 0x0706_0504_0302_0100;
        let k1 = 0x0f0e_0d0c_0b0a_0908;
        let msg: Vec<u8> = (0u8..15).collect();
        assert_eq!(siphash(k0, k1, &msg), 0xa129_ca61_49be_45e5);
    }

    #[test]
    fn distinct_inputs_and_keys_differ() {
        assert_ne!(siphash(1, 2, b"/usr/bin/curl"), siphash(1, 2, b"/usr/bin/wget"));
        // Same input, different key → different hash (the whole point of #3).
        assert_ne!(siphash(1, 2, b"/usr/bin/curl"), siphash(9, 9, b"/usr/bin/curl"));
    }

    #[test]
    fn streaming_walk_matches_one_shot() {
        // The executable spec for the eBPF walk: every prefix/component hash
        // the streaming pass emits must equal the one-shot SipHash of that
        // exact substring. If this holds, a faithful BPF port agrees with
        // userspace byte-for-byte.
        let (k0, k1) = (0xdead_beef_0bad_f00d, 0x0123_4567_89ab_cdef);
        for path in [
            &b"/a/bb/ccc/exe"[..],
            b"/",
            b"x",
            b"/home/u/Downloads/installer.sh",
            b"no-slashes-here",
            b"/exactly8/aligned/", // exercise 8-byte word boundaries
        ] {
            let (full, folder, basename, ancestors) = streaming_walk(k0, k1, path);
            assert_eq!(full, siphash(k0, k1, path), "full {path:?}");

            // collect the byte offsets of every '/'
            let slashes: Vec<usize> = path
                .iter()
                .enumerate()
                .filter(|(_, &b)| b == b'/')
                .map(|(i, _)| i)
                .collect();
            assert_eq!(ancestors.len(), slashes.len(), "ancestor count {path:?}");
            for (k, &end) in slashes.iter().enumerate() {
                assert_eq!(ancestors[k], siphash(k0, k1, &path[..=end]), "anc {k} {path:?}");
            }
            if let Some(&last) = slashes.last() {
                assert_eq!(folder, siphash(k0, k1, &path[..=last]), "folder {path:?}");
                assert_eq!(basename, siphash(k0, k1, &path[last + 1..]), "base {path:?}");
            } else {
                // no slash: basename is the whole thing, folder never set
                assert_eq!(basename, siphash(k0, k1, path), "base-noslash {path:?}");
            }
        }
    }
}
