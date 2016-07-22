use std::io::prelude::*;
use std::fs::File;
use std::collections::HashSet;

use rand::{thread_rng, Rng};

use serialize::base64::FromBase64;
use serialize::hex::ToHex;

use ssl::crypto::symm::{self, encrypt, decrypt};

fn pad_pkcs7(mut data: Vec<u8>, blocksize: usize) -> Vec<u8> {
    assert!(blocksize < 256);

    let len = data.len();
    let rem = len % blocksize;
    let pad = (blocksize - rem) as u8;

    for _ in 0..pad {
        data.push(pad);
    }

    data
}

fn unpad_pkcs7(mut data: Vec<u8>) -> Vec<u8> {
    let len = data.len();
    let pad = data[len - 1] as usize;
    data.truncate(len - pad);
    data
}

#[test]
fn set_2_9() {
    let mut data = "YELLOW SUBMARINE".to_string().into_bytes();
    data = pad_pkcs7(data, 20);
    assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04", &String::from_utf8_lossy(&data));
    data = "AAAABBBBCC".to_string().into_bytes();
    data = pad_pkcs7(data, 4);
    assert_eq!("AAAABBBBCC\x02\x02", &String::from_utf8_lossy(&data));
    data = "AAAABBBB".to_string().into_bytes();
    data = pad_pkcs7(data, 4);
    assert_eq!("AAAABBBB\x04\x04\x04\x04", &String::from_utf8_lossy(&data));
}

#[test]
fn test_unpad_pkcs7() {
    let mut data = "AAAABBBB\x04\x04\x04\x04".to_string().into_bytes();
    data = unpad_pkcs7(data);
    assert_eq!("AAAABBBB", &String::from_utf8_lossy(&data));
    data = "AAAABBBBCCC\x01".to_string().into_bytes();
    data = unpad_pkcs7(data);
    assert_eq!("AAAABBBBCCC", &String::from_utf8_lossy(&data));
}

fn encrypt_cbc(data: &[u8], key: &[u8], iv: &[u8], blocksize: usize) -> Vec<u8> {
    let mut data_ = data.to_vec();
    data_ = pad_pkcs7(data_, blocksize);

    let len = data_.len();
    let blocks = len / blocksize;
    let zeros = vec![0_u8; key.len()];
    let mut out: Vec<u8> = Vec::with_capacity(len);

    for i in 0..blocks {
        let mut m_i: Vec<u8> = Vec::with_capacity(blocksize);

        let data_view = &data_[i*blocksize..(i+1)*blocksize];
        if i == 0 {
            for j in 0..blocksize {
                m_i.push(data_view[j] ^ iv[j]);
            }
        } else {
            let out_view = &out[(i-1)*blocksize..i*blocksize];
            for j in 0..blocksize {
                m_i.push(data_view[j] ^ out_view[j]);
            }
        }

        m_i = encrypt(symm::Type::AES_128_ECB, key, &zeros, &m_i);
        m_i.truncate(blocksize);
        out.extend_from_slice(&m_i);
    }

    out
}

fn decrypt_cbc(data: &[u8], key: &[u8], iv: &[u8], blocksize: usize) -> Vec<u8> {
    assert!(data.len() % blocksize == 0, "data must be multiple length of blocksize");

    let blocks = data.len() / blocksize;
    let zeros = vec![0_u8; key.len()];
    let mut out: Vec<u8> = Vec::with_capacity(data.len());

    for i in 0..blocks {
        let iv_ = if i == 0 { iv } else { &zeros };

        let mut m_i =
            if i == blocks - 1 {
                let mut block = data[i*blocksize..(i+1)*blocksize].to_vec();
                block.extend_from_slice(&zeros);
                decrypt(symm::Type::AES_128_ECB, key, iv_, &block)
            } else {
                decrypt(symm::Type::AES_128_ECB, key, iv_, &data[i*blocksize..(i+2)*blocksize])
            };

        if i == 0 {
            for j in 0..blocksize {
                m_i[j] ^= iv[j];
            }
        } else {
            let data_view = &data[(i-1)*blocksize..i*blocksize];
            for j in 0..blocksize {
                m_i[j] ^= data_view[j];
            }
        }

        out.extend_from_slice(&m_i);
    }

    unpad_pkcs7(out)
}

pub fn set_2_10() {
    let mut f = File::open("./data/10.txt").unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    let bytes = s.from_base64().unwrap();

    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0_u8; key.len()];

    let out1 = decrypt(symm::Type::AES_128_CBC, key, &iv, &bytes);
    let out2 = decrypt_cbc(&bytes, key, &iv, 16);

    let m1 = String::from_utf8_lossy(&out1);
    let m2 = String::from_utf8_lossy(&out2);

    assert_eq!(&m1, &m2);
}

#[test]
fn test_encrypt_cbc() {
    let data = "DOST THOU JEER AND T-TAUNT ME IN THE TEETH?".as_bytes();

    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0_u8; key.len()];

    let out1 = encrypt(symm::Type::AES_128_CBC, key, &iv, data).to_hex();
    let out2 = encrypt_cbc(data, key, &iv, 16).to_hex();

    assert_eq!(&out1, &out2);
}

#[test]
fn test_encrypt_decrypt_cbc() {
    let data = "DOS'T THOU JEER AND T-TAUNT ME IN THE TEETH?".as_bytes();

    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0_u8; key.len()];

    let cipher1 = encrypt(symm::Type::AES_128_CBC, key, &iv, data);
    let cipher2 = encrypt_cbc(data, key, &iv, 16);

    assert_eq!(cipher1.to_hex(), cipher2.to_hex());

    let out1 = decrypt(symm::Type::AES_128_CBC, key, &iv, &cipher1);
    let out2 = decrypt_cbc(&cipher2, key, &iv, 16);

    assert_eq!(out1.to_hex(), out2.to_hex());
}

#[derive(PartialEq, Eq, Debug)]
enum AESMode {
    EBC,
    CBC,
}

fn encryption_oracle(input: &[u8]) -> (AESMode, Vec<u8>) {
    let mut rng = thread_rng();

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

    let mode = if rng.gen::<bool>() { AESMode::EBC } else { AESMode::CBC };

    let out = match mode {
            AESMode::EBC => decrypt(symm::Type::AES_128_ECB, &key, &iv, &m),
            AESMode::CBC => decrypt(symm::Type::AES_128_CBC, &key, &iv, &m),
        };

    (mode, out)
}

fn guess_mode(ciphertext: &[u8]) -> AESMode {
    let mut set = HashSet::new();
    for chunk in ciphertext.chunks(16) {
        let hex = chunk.to_hex();
        if set.contains(&hex) {
            return AESMode::EBC;
        }
        set.insert(hex);
    }
    AESMode::CBC
}

pub fn set_2_11() {
    // choose a plaintext which will force a repeated block only in EBC mode, regardless of
    // key, iv, and (small) random padding.
    let controlled_plaintext = "[AAAAAAAAAAAAAA][AAAAAAAAAAAAAA][AAAAAAAAAAAAAA]".as_bytes();
    let runs = 1000;

    for _ in 0..runs {
        let (mode, ciphertext) = encryption_oracle(controlled_plaintext);
        assert_eq!(mode, guess_mode(&ciphertext));
    }

    println!("Successfully guessed the correct AES 128 Mode {} times!", runs);
}

fn encryption_oracle_2(input: &[u8], unknown: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = [0_u8; 16];

    let mut data: Vec<u8> = Vec::with_capacity(input.len() + unknown.len());
    data.extend_from_slice(input);
    data.extend_from_slice(unknown);

    encrypt(symm::Type::AES_128_ECB, key, &iv, &data)
}

pub fn set_2_12() {
    let mut rng = thread_rng();
    let unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                   YnkK".from_base64().unwrap();
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);

    // Determine blocksize
    let mut i = 1;
    let mut blocksize = 0;
    loop {
        let input = vec!['A' as u8; 2*i];
        let out = encryption_oracle_2(&input, &unknown, &key);

        let block1 = &out[0..i];
        let block2 = &out[i..2*i];
        if block1 == block2 {
            blocksize = i;
            break;
        }
        i += 1;
    }

    // Determine ciphertext length
    let len = encryption_oracle_2("".as_bytes(), &unknown, &key).len();
    let mut ctxt_len = 0;
    for i in 1..blocksize+1 {
        let input = vec!['A' as u8; i];
        let new_len = encryption_oracle_2(&input, &unknown, &key).len();
        if new_len != len {
            ctxt_len = new_len - blocksize - i;
            break;
        }
    }

    println!("blocksize = {}", blocksize);
    println!("ciphertext length = {}", ctxt_len);

    let mut queries = 0;

    // Decrypt ciphertext byte-by-byte
    let mut plaintext: Vec<u8> = Vec::with_capacity(ctxt_len);
    for i in 0..ctxt_len {
        for char_guess in 0...255 {
            let mut input: Vec<u8> = Vec::new();
            
            let k = (i as i32) - (blocksize as i32) + 1;

            for j in k..(i as i32) {
                if j < 0 {
                    input.push('A' as u8);
                } else {
                    input.push(plaintext[j as usize]);
                }
            }

            input.push(char_guess);

            for _ in 0..(blocksize - (i % blocksize)) - 1 {
                input.push('A' as u8);
            }

            let out = encryption_oracle_2(&input, &unknown, &key);
            queries += 1;

            let b_i = (i / blocksize) + 1;

            let block1 = &out[0..blocksize];
            let block2 = &out[b_i*blocksize..(b_i+1)*blocksize];

            if block1 == block2 {
                plaintext.push(char_guess);
                break;
            }
        }
    }

    println!("queries = {}", queries);
    println!("===");
    println!("{}", String::from_utf8_lossy(&plaintext));
}
