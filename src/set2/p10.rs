use std::io::prelude::*;
use std::fs::File;

use ssl::crypto::symm::{self, decrypt, encrypt};
use crypto::pkcs7;
use serialize::base64::FromBase64;
use serialize::hex::ToHex;

fn encrypt_cbc(data: &[u8], key: &[u8], iv: &[u8], blocksize: usize) -> Vec<u8> {
    let mut data_ = data.to_vec();
    data_ = pkcs7::pad(data_, blocksize);

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

    pkcs7::unpad(out)
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
fn test_decrypt_cbc() {
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
