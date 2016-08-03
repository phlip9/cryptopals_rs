use rand::{Rng, weak_rng};
use rust_crypto::digest::Digest;

use util::xor_bytes;
use sha1::Sha1;

fn valid_mac(key: &[u8], msg: &[u8], mac: &[u8]) -> bool {
    let mut m = Sha1::new();
    let mut out = [0_u8; 20];
    m.input(key);
    m.input(msg);
    m.result(&mut out);
    &out == mac
}

#[test]
fn run() {
    let mut m = Sha1::new();
    let mut rng = weak_rng();
    let key: [u8; 16] = rng.gen();
    let s = b"The quick brown fox jumps over the lazy dog";

    let mut mac = [0_u8; 20];
    m.input(&key);
    m.input(s);
    m.result(&mut mac);

    assert!(valid_mac(&key, s, &mac));

    let s2 = xor_bytes(s, &[0x12_u8, 0x34, 0x56, 0x78]);
    assert!(!valid_mac(&key, &s2, &mac));

    let mut s3 = s.to_vec();
    s3[10] ^= 1;
    assert!(!valid_mac(&key, &s3, &mac));
}
