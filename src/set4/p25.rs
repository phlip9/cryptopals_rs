use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

use rand::{Rng, weak_rng};
use serialize::base64::FromBase64;
use ssl::crypto::symm::{self, decrypt};

use crypto::aes;
use util::hexdump;

fn edit_oracle(key: &[u8], nonce: u64, ctxt: &[u8], offset: usize, txt: &[u8]) -> Vec<u8> {
    let mut ptxt = aes::ctr(key, nonce, ctxt);
    for i in 0..txt.len() {
        if i + offset >= ptxt.len() {
            ptxt.push(txt[i]);
        } else {
            ptxt[i + offset] = txt[i];
        }
    }
    aes::ctr(key, nonce, &ptxt)
}

#[test]
fn run() {
    let mut rng = weak_rng();
    let key: [u8; 16] = rng.gen();
    let nonce: u64 = rng.gen();

    let ptxt = File::open("./data/25.txt")
        .map(|f| BufReader::new(f))
        .and_then(|mut b| {
            let mut s = String::new();
            b.read_to_string(&mut s)
                .map(|_| s)
        })
        .map(|s| s.from_base64().unwrap())
        .map(|c| {
            decrypt(symm::Type::AES_128_ECB, "YELLOW SUBMARINE".as_bytes(), &[0u8; 16], &c)
        })
        .unwrap();

    let ctxt = aes::ctr(&key, nonce, &ptxt);

    // Attacker

    // edit the itermediary plaintext to be the ciphertext. the same keystream
    // will be used to "encrypt" the ciphertext, giving us the plaintext as a
    // result.
    let ptxt_recovered = edit_oracle(&key, nonce, &ctxt, 0, &ctxt);

    hexdump(&ptxt);
    assert_eq!(&ptxt, &ptxt_recovered);
}
