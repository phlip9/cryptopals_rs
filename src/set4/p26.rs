use rand::{Rng, weak_rng};

use crypto::aes;

fn encryption_oracle(key: &[u8], nonce: u64, input: &[u8]) -> Vec<u8> {
    let prefix = b"comment1=cooking%20MCs;userdata=";
    let postfix = b";comment2=%20like%20a%20pound%20of%20bacon";

    let input_filtered = input.iter()
        .filter(|&&c| c != b';' && c != b'=')
        .cloned()
        .collect::<Vec<u8>>();

    let mut data = prefix.to_vec();
    data.extend_from_slice(&input_filtered);
    data.extend_from_slice(postfix);

    aes::ctr(key, nonce, &data)
}

fn decryption_oracle(key: &[u8], nonce: u64, data: &[u8]) -> Vec<u8> {
    aes::ctr(key, nonce, data)
}

#[test]
fn run() {
    let mut rng = weak_rng();
    let key: [u8; 16] = rng.gen();
    let nonce: u64 = rng.gen();

    let input = b"AAAAAAAAAAA";
    let subst = b";admin=true";
    let mut ctxt = encryption_oracle(&key, nonce, input);
    for i in 0..subst.len() {
        ctxt[i + 32] ^= input[i] ^ subst[i];
    }
    let ptxt = decryption_oracle(&key, nonce, &ctxt);

    let is_admin = String::from_utf8_lossy(&ptxt)
        .split(';')
        .map(|pair| pair.split('=').collect::<Vec<&str>>())
        .filter(|pair| pair.len() == 2 && pair[0] == "admin" && pair[1] == "true")
        .count() == 1;

    assert!(is_admin);
}
