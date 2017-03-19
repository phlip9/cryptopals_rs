use std::collections::HashSet;

use rand::{Rng, weak_rng};
use serialize::hex::ToHex;
use ssl::symm::{self, encrypt};

#[derive(PartialEq, Eq, Debug)]
enum AESMode {
    ECB,
    CBC,
}

fn encryption_oracle(input: &[u8]) -> (AESMode, Vec<u8>) {
    let mut rng = weak_rng();
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);
    let mut iv = [0_u8; 16];
    rng.fill_bytes(&mut iv);

    let mut m: Vec<u8> = Vec::new();

    let pad_left_len: usize = rng.gen_range(5, 10);
    let pad_left = (0..pad_left_len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

    let pad_right_len: usize = rng.gen_range(5, 10);
    let pad_right = (0..pad_right_len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

    m.extend_from_slice(&pad_left);
    m.extend_from_slice(input);
    m.extend_from_slice(&pad_right);

    let mode = if rng.gen::<bool>() { AESMode::ECB } else { AESMode::CBC };

    let out = match mode {
            AESMode::ECB => encrypt(symm::Cipher::aes_128_ecb(), &key, None, &m).unwrap(),
            AESMode::CBC => encrypt(symm::Cipher::aes_128_cbc(), &key, Some(&iv), &m).unwrap(),
        };

    (mode, out)
}

fn guess_mode(ciphertext: &[u8]) -> AESMode {
    let mut set = HashSet::new();
    for chunk in ciphertext.chunks(16) {
        let hex = chunk.to_hex();
        if set.contains(&hex) {
            return AESMode::ECB;
        }
        set.insert(hex);
    }
    AESMode::CBC
}

#[test]
fn run() {
    // choose a plaintext which will force a repeated block only in ECB mode, regardless of
    // key, iv, and (small) random padding.
    let controlled_plaintext = "[AAAAAAAAAAAAAA][AAAAAAAAAAAAAA][AAAAAAAAAAAAAA]".as_bytes();
    let runs = 1000;

    for _ in 0..runs {
        let (mode, ciphertext) = encryption_oracle(controlled_plaintext);
        assert_eq!(mode, guess_mode(&ciphertext));
    }

    println!("Successfully guessed the correct AES 128 Mode {} times!", runs);
}
