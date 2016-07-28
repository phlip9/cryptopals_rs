pub mod pkcs7 {
    pub fn pad(mut data: Vec<u8>, blocksize: usize) -> Vec<u8> {
        assert!(blocksize < 256);

        let len = data.len();
        let rem = len % blocksize;
        let pad = (blocksize - rem) as u8;

        for _ in 0..pad {
            data.push(pad);
        }

        data
    }

    pub fn unpad(mut data: Vec<u8>) -> Option<Vec<u8>> {
        let len = data.len();
        let pad = data[len - 1] as usize;
        if pad > len || pad == 0 {
            return None;
        }
        for i in 0..pad {
            let idx = len - i - 1;
            if data[idx] != pad as u8 {
                return None;
            }
        }
        data.truncate(len - pad);
        Some(data)
    }
}

pub mod aes {
    use ssl::crypto::symm::{self, Crypter};

    pub fn ctr(key: &[u8], n: u64, data: &[u8]) -> Vec<u8> {
        let iv = [0_u8; 16];
        let keystream = (0..)
            .flat_map(|c: u64| {
                let ctr_bytes = [
                    ( n & 0x00000000000000FF) as u8,
                    ((n & 0x000000000000FF00) >> 8 ) as u8,
                    ((n & 0x0000000000FF0000) >> 16) as u8,
                    ((n & 0x00000000FF000000) >> 24) as u8,
                    ((n & 0x000000FF00000000) >> 32) as u8,
                    ((n & 0x0000FF0000000000) >> 40) as u8,
                    ((n & 0x00FF000000000000) >> 48) as u8,
                    ((n & 0xFF00000000000000) >> 56) as u8,
                    ( c & 0x00000000000000FF) as u8,
                    ((c & 0x000000000000FF00) >> 8 ) as u8,
                    ((c & 0x0000000000FF0000) >> 16) as u8,
                    ((c & 0x00000000FF000000) >> 24) as u8,
                    ((c & 0x000000FF00000000) >> 32) as u8,
                    ((c & 0x0000FF0000000000) >> 40) as u8,
                    ((c & 0x00FF000000000000) >> 48) as u8,
                    ((c & 0xFF00000000000000) >> 56) as u8
                ];
                let cr = Crypter::new(symm::Type::AES_128_ECB);
                cr.init(symm::Mode::Encrypt, &key, &iv);
                cr.pad(false);
                let mut r = cr.update(&ctr_bytes);
                let rest = cr.finalize();
                r.extend(rest.into_iter());
                r.into_iter()
            });
        data.iter()
            .zip(keystream)
            .map(|(d, e)| d ^ e)
            .collect::<Vec<_>>()
    }
}

pub mod cbc {
    use ssl::crypto::symm::{self, decrypt as ssl_decrypt, encrypt as ssl_encrypt};
    use super::pkcs7;

    pub fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
        let blocksize = key.len();
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

            m_i = ssl_encrypt(symm::Type::AES_128_ECB, key, &zeros, &m_i);
            m_i.truncate(blocksize);
            out.extend_from_slice(&m_i);
        }

        out
    }

    pub fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        let blocksize = key.len();
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
                    ssl_decrypt(symm::Type::AES_128_ECB, key, iv_, &block)
                } else {
                    ssl_decrypt(symm::Type::AES_128_ECB, key, iv_, &data[i*blocksize..(i+2)*blocksize])
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
}

#[cfg(test)]
mod test {
    use std::io::prelude::*;
    use std::fs::File;

    use ssl::crypto::symm::{self, decrypt, encrypt};
    use serialize::base64::FromBase64;
    use serialize::hex::ToHex;

    use super::pkcs7::{pad, unpad};
    use super::cbc;
    use super::aes;

    #[test]
    fn test_pkcs7_pad() {
        let mut data = "AAAABBBBCC".to_string().into_bytes();
        data = pad(data, 4);
        assert_eq!("AAAABBBBCC\x02\x02", &String::from_utf8_lossy(&data));
        data = "AAAABBBB".to_string().into_bytes();
        data = pad(data, 4);
        assert_eq!("AAAABBBB\x04\x04\x04\x04", &String::from_utf8_lossy(&data));
    }

    #[test]
    fn test_pkcs7_unpad() {
        let mut a = "ABCD\x04\x04\x04\x04".as_bytes().to_vec();
        a = unpad(a).unwrap();
        assert_eq!(a, "ABCD".as_bytes());
        a = "ABCD\x01\x02\x03\x04".as_bytes().to_vec();
        let mut res = unpad(a);
        assert!(res.is_none());
        a = "ABCD\x04\x04".as_bytes().to_vec();
        res = unpad(a);
        assert!(res.is_none());
    }

    #[test]
    fn test_cbc_encrypt() {
        let data = "DOST THOU JEER AND T-TAUNT ME IN THE TEETH?".as_bytes();

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = vec![0_u8; key.len()];

        let out1 = encrypt(symm::Type::AES_128_CBC, key, &iv, data).to_hex();
        let out2 = cbc::encrypt(key, &iv, data).to_hex();

        assert_eq!(&out1, &out2);
    }

    #[test]
    fn test_cbc_decrypt() {
        let mut f = File::open("./data/10.txt").unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        let bytes = s.from_base64().unwrap();

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = vec![0_u8; key.len()];

        let out1 = decrypt(symm::Type::AES_128_CBC, key, &iv, &bytes);
        let out2 = cbc::decrypt(key, &iv, &bytes).unwrap();

        let m1 = String::from_utf8_lossy(&out1);
        let m2 = String::from_utf8_lossy(&out2);

        assert_eq!(&m1, &m2);
    }

    #[test]
    fn test_cbc_encrypt_decrypt() {
        let data = "DOS'T THOU JEER AND T-TAUNT ME IN THE TEETH?".as_bytes();

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = vec![0_u8; key.len()];

        let cipher1 = encrypt(symm::Type::AES_128_CBC, key, &iv, data);
        let cipher2 = cbc::encrypt(key, &iv, data);

        assert_eq!(cipher1.to_hex(), cipher2.to_hex());

        let out1 = decrypt(symm::Type::AES_128_CBC, key, &iv, &cipher1);
        let out2 = cbc::decrypt(key, &iv, &cipher2).unwrap();

        assert_eq!(out1.to_hex(), out2.to_hex());
    }

    #[test]
    fn test_aes_ctr() {
        let ctxt = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let data = ctxt.from_base64().unwrap();
        let key = "YELLOW SUBMARINE".as_bytes();
        let nonce = 0_u64;
        let out = aes::ctr(key, nonce, &data);
        assert_eq!(out.as_slice(), "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".as_bytes());
        let ctxt2 = aes::ctr(key, nonce, &out);
        assert_eq!(&ctxt2, &data);
    }
}
