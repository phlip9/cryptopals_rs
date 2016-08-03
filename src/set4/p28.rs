use rand::{Rng, weak_rng};
use serialize::hex::ToHex;

use util::{sha1, xor_bytes};

fn valid_mac(key: &[u8], msg: &[u8], mac: &[u8]) -> bool {
    let mut mac_preimage = key.to_vec();
    mac_preimage.extend_from_slice(msg);
    let out = sha1(&mac_preimage);
    out == mac
}

#[test]
fn run() {
    let s = b"The quick brown fox jumps over the lazy dog";
    let d = sha1(s).to_hex();
    assert_eq!(&d, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");

    let mut rng = weak_rng();
    let key: [u8; 16] = rng.gen();
    let mut mac_preimage = key.to_vec();
    mac_preimage.extend_from_slice(s);
    let mac = sha1(&mac_preimage);

    assert!(valid_mac(&key, s, &mac));

    let s2 = xor_bytes(s, &[0x12_u8, 0x34, 0x56, 0x78]);
    assert!(!valid_mac(&key, &s2, &mac));

    let mut s3 = s.to_vec();
    s3[10] ^= 1;
    assert!(!valid_mac(&key, &s3, &mac));
}
