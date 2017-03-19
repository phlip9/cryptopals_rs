use rand::{Rng, weak_rng};
use serialize::base64::FromBase64;
use ssl::symm::{self, encrypt, decrypt};

use util::xor_bytes;

fn encryption_oracle(key: &[u8], input: &[u8]) -> Vec<u8> {
    let iv = Some(key);
    encrypt(symm::Cipher::aes_128_cbc(), key, iv, input).unwrap()
}

fn decryption_oracle(key: &[u8], data: &[u8]) -> Vec<u8> {
    let iv = Some(key);
    let ptxt = decrypt(symm::Cipher::aes_128_cbc(), key, iv, data).unwrap();

    let invalid = ptxt.iter()
        .find(|&&b| b < 32 || b >= 127)
        .is_some();

    if invalid {
        println!("Oh no there's an error!");
    }

    ptxt
}

// k=IV recovery attack
// ---
// C_1' = C_1
// C_2' = 0
// C_3' = C_1
// P_1' = D_k(C_1') ^ k
//      = D_k(C_1) ^ k
// P_3' = D_k(C_3') ^ C_2'
//      = D_k(C_1) ^ 0
//      = D_k(C_1)
//    k = P_1' ^ P_3'
//      = D_k(C_1') ^ k ^ D_k(C_1)
//      = k

#[test]
fn run() {
    let mut rng = weak_rng();
    let key: [u8; 16] = rng.gen();

    let msg = "RE9TJ1QgVEhPVSBQUkFURSwgUk9HVUU/PyBET1MnVCBUSE9VIEpFRVIgQU5EIFQ\
    tVEFVTlQgTUUgSU4gVEhFIFRFRVRIPz8K"
        .from_base64()
        .unwrap();

    let ctxt = encryption_oracle(&key, &msg);

    let mut new_ctxt = ctxt[0..16].to_vec();
    new_ctxt.extend_from_slice(&[0_u8; 16]);
    new_ctxt.extend_from_slice(&ctxt[0..16]);
    new_ctxt.extend_from_slice(&ctxt[48..]);

    let ptxt = decryption_oracle(&key, &new_ctxt);
    let key_recovered = xor_bytes(&ptxt[0..16], &ptxt[32..48]);

    assert_eq!(&key_recovered, &key);
}
