use rand::{Rng, weak_rng};
use ssl::symm::{self, encrypt, decrypt};

fn encryption_oracle(key: &[u8], iv: &[u8], input: &[u8]) -> Vec<u8> {
    let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
    let postfix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

    let input_filtered = input.iter()
        .filter(|&&c| c != ';' as u8 && c != '=' as u8)
        .cloned()
        .collect::<Vec<u8>>();

    let mut data = prefix.to_vec();
    data.extend_from_slice(&input_filtered);
    data.extend_from_slice(postfix);

    encrypt(symm::Cipher::aes_128_cbc(), key, Some(iv), &data).unwrap()
}

fn decryption_oracle(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    decrypt(symm::Cipher::aes_128_cbc(), key, Some(iv), data).unwrap()
}

#[test]
fn run() {
    let mut rng = weak_rng();
    let blocksize = 16;
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);
    let mut iv = [0_u8; 16];
    rng.fill_bytes(&mut iv);

    //   AAAAAAAAAAAAAAAA|AAAAAAAAAAAAAAAA
    // ^ 00000;admin=true|................
    // ^ 00000AAAAAAAAAAA|................
    // = AAAAA...........|AAAAA;admin=true

    let input = ['A' as u8; 2*16];
    let mut ciphertext = encryption_oracle(&key, &iv, &input);

    let block1 = "\x00\x00\x00\x00\x00;admin=true".as_bytes();
    let block2 = "\x00\x00\x00\x00\x00AAAAAAAAAAA".as_bytes();
    for i in 0..blocksize {
        ciphertext[i + 2*blocksize] ^= block1[i] ^ block2[i];
    }

    let plaintext = decryption_oracle(&key, &iv, &ciphertext);
    let string = String::from_utf8_lossy(&plaintext);
    println!("{}", &string);

    let is_admin = string.split(';')
        .map(|pair| pair.split('=').collect::<Vec<&str>>())
        .filter(|pair| pair.len() == 2 && pair[0] == "admin" && pair[1] == "true")
        .count() == 1;

    assert!(is_admin);
}
