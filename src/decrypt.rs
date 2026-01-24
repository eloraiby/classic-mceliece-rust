//! Decryption function to turn ciphertext into a ciphertext using the secret key

use crate::{
    benes::support_gen,
    bm::bm,
    gf::gf_iszero,
    macros::sub,
    params::{COND_BYTES, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T},
    root::root,
    synd::synd,
    util::load_gf,
};

#[cfg(feature = "embedded-workspace")]
struct DecryptWorkspace {
    r: [u8; SYS_N / 8],
    g: [u16; SYS_T + 1],
    l: [u16; SYS_N],
    s: [u16; SYS_T * 2],
    s_cmp: [u16; SYS_T * 2],
    locator: [u16; SYS_T + 1],
    images: [u16; SYS_N],
}

#[cfg(feature = "embedded-workspace")]
static mut DECRYPT_WS: DecryptWorkspace = DecryptWorkspace {
    r: [0u8; SYS_N / 8],
    g: [0u16; SYS_T + 1],
    l: [0u16; SYS_N],
    s: [0u16; SYS_T * 2],
    s_cmp: [0u16; SYS_T * 2],
    locator: [0u16; SYS_T + 1],
    images: [0u16; SYS_N],
};

/// Niederreiter decryption with the Berlekamp decoder.
///
/// It takes as input the secret key `sk` and a ciphertext `c`.
/// It returns an error vector in `e` and the return value indicates success (0) or failure (1)
pub(crate) fn decrypt(
    e: &mut [u8; SYS_N / 8],
    sk: &[u8; IRR_BYTES + COND_BYTES],
    c: &[u8; SYND_BYTES],
) -> u8 {
    let mut t: u16;
    let mut w: i32 = 0;

    #[cfg(feature = "embedded-workspace")]
    let (r, g, l, s, s_cmp, locator, images) = {
        let ws = unsafe { &mut DECRYPT_WS };
        (
            &mut ws.r,
            &mut ws.g,
            &mut ws.l,
            &mut ws.s,
            &mut ws.s_cmp,
            &mut ws.locator,
            &mut ws.images,
        )
    };
    #[cfg(feature = "embedded-workspace")]
    {
        r.fill(0);
        g.fill(0);
        l.fill(0);
        s.fill(0);
        s_cmp.fill(0);
        locator.fill(0);
        images.fill(0);
    }

    #[cfg(not(feature = "embedded-workspace"))]
    let mut r = [0u8; SYS_N / 8];
    #[cfg(not(feature = "embedded-workspace"))]
    let mut g = [0u16; SYS_T + 1];
    #[cfg(not(feature = "embedded-workspace"))]
    let mut l = [0u16; SYS_N];
    #[cfg(not(feature = "embedded-workspace"))]
    let mut s = [0u16; SYS_T * 2];
    #[cfg(not(feature = "embedded-workspace"))]
    let mut s_cmp = [0u16; SYS_T * 2];
    #[cfg(not(feature = "embedded-workspace"))]
    let mut locator = [0u16; SYS_T + 1];
    #[cfg(not(feature = "embedded-workspace"))]
    let mut images = [0u16; SYS_N];
    #[cfg(not(feature = "embedded-workspace"))]
    let (r, g, l, s, s_cmp, locator, images) = (
        &mut r,
        &mut g,
        &mut l,
        &mut s,
        &mut s_cmp,
        &mut locator,
        &mut images,
    );

    r[..SYND_BYTES].copy_from_slice(&c[..SYND_BYTES]);

    r[SYND_BYTES..SYS_N / 8].fill(0);

    for (i, chunk) in sk.chunks(2).take(SYS_T).enumerate() {
        g[i] = load_gf(sub!(chunk, 0, 2));
    }
    g[SYS_T] = 1;

    support_gen(l, sub!(sk, IRR_BYTES, COND_BYTES));

    synd(s, g, l, r);

    bm(locator, s);

    root(images, locator, l);

    e[0..SYS_N / 8].fill(0);

    for i in 0..SYS_N {
        t = gf_iszero(images[i]) & 1;

        e[i / 8] |= (t << (i % 8)) as u8;
        w += t as i32;
    }

    synd(s_cmp, g, l, e);

    let mut check = w as u16;
    check ^= SYS_T as u16;

    for i in 0..SYS_T * 2 {
        check |= s[i] ^ s_cmp[i];
    }

    check = check.wrapping_sub(1);
    check >>= 15;

    (check ^ 1) as u8
}

#[cfg(test)]
#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
mod tests {
    use super::*;
    use crate::test_utils::TestData;

    #[test]
    fn test_decrypt() {
        let sk = TestData::new().u8vec("mceliece8192128f_sk1"); // TODO: sk has wrong size … IRR_BYTES + COND_BYTES required
        let mut c = TestData::new().u8vec("mceliece8192128f_ct1");
        let expected_error_vector = TestData::new().u8vec("mceliece8192128f_decrypt_errvec");

        let mut actual_error_vector = [0u8; 1 + SYS_N / 8];
        actual_error_vector[0] = 2;

        decrypt(
            sub!(mut actual_error_vector, 1, SYS_N / 8),
            sub!(sk, 40, IRR_BYTES + COND_BYTES),
            sub!(mut c, 0, SYND_BYTES),
        );

        assert_eq!(
            &actual_error_vector[1..SYS_N / 8],
            &expected_error_vector[1..SYS_N / 8]
        );
    }
}
