use rand::{Rng, weak_rng};
use serialize::base64::FromBase64;
use ssl::crypto::symm::{self, encrypt};

use math::Gcd;

fn encryption_oracle(key: &[u8], prefix: &[u8], input: &[u8], unknown: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&prefix);
    m.extend_from_slice(&input);
    m.extend_from_slice(&unknown);
    let iv = [0_u8; 16];
    encrypt(symm::Type::AES_128_ECB, key, &iv, &m)
}

#[test]
fn run() {
    // Oracle Setup
    let unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                   YnkK".from_base64().unwrap();
    let mut rng = weak_rng();
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);

    let prefix = {
        let prefix_len: usize = rng.gen_range(1, 16*10);
        (0..prefix_len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>()
    };

    // Attacker

    // Determine blocksize
    let blocksize = {
        let lens = (1..50)
            .map(|i| {
                let input = vec!['A' as u8; i];
                let out = encryption_oracle(&key, &prefix, &input, &unknown);
                out.len()
            })
            .collect::<Vec<_>>();

        let len = lens[0];
        lens.iter().fold(len, |a, &b| a.gcd(b))
    };

    println!("blocksize = {}", blocksize);

    //// Determine prefix length
    let prefix_len = {
        let mut len = 0;
        let mut flag = false;
        for i in 0..blocksize+1 {
            if flag { break; }
            let input = vec!['A' as u8; i + 2*blocksize];
            let out = encryption_oracle(&key, &prefix, &input, &unknown);
            let blocks = out.len() / blocksize;
            for j in 0..blocks-1 {
                let block1 = &out[j*blocksize..(j+1)*blocksize];
                let block2 = &out[(j+1)*blocksize..(j+2)*blocksize];
                if block1 == block2 {
                    len = j*blocksize - i;
                    flag = true;
                    break;
                }
            }
        }
        len
    };

    println!("prefix_len = {}", prefix_len);

    // Determine unknown length
    let unknown_len = {
        let mut len = 0;
        let prev_len = encryption_oracle(&key, &prefix, "".as_bytes(), &unknown).len();
        for i in 1..blocksize+1 {
            let input = vec!['A' as u8; i];
            let new_len = encryption_oracle(&key, &prefix, &input, &unknown).len();
            if new_len != prev_len {
                len = new_len - blocksize - i - prefix_len;
                break;
            }
        }
        len
    };

    println!("unknown_len = {}", unknown_len);

    // Decrypt unknown text byte-by-byte
    let mut plaintext: Vec<u8> = Vec::with_capacity(unknown_len);
    let prefix_padding = blocksize - (prefix_len % blocksize);
    let prefix_offset = prefix_len + prefix_padding;

    println!("prefix_padding = {}", prefix_padding);
    println!("prefix_offset = {}", prefix_offset);

    for i in 0..unknown_len {
        let mut input: Vec<u8> = vec!['A' as u8; prefix_padding];

        for char_guess in 0...255 {
            let k = (i as i32) - (blocksize as i32) + 1;

            for j in k..(i as i32) {
                if j < 0 {
                    input.push('A' as u8);
                } else {
                    input.push(plaintext[j as usize]);
                }
            }

            input.push(char_guess);
        }

        for _ in 0..(blocksize - (i % blocksize)) - 1 {
            input.push('A' as u8);
        }

        let out = encryption_oracle(&key, &prefix, &input, &unknown);

        let b_i = (i / blocksize) + 256;

        let cipher_block = &out[b_i*blocksize+prefix_offset..(b_i+1)*blocksize+prefix_offset];

        // search for input block with same AES ECB block signature
        for char_guess in 0...255 {
            let j = char_guess as usize;
            let guess_block = &out[j*blocksize+prefix_offset..(j+1)*blocksize+prefix_offset];
            if guess_block == cipher_block {
                plaintext.push(char_guess);
                break;
            }
        }
    }

    let expected = "Rollin' in my 5.0\n\
        With my rag-top down so my hair can blow\n\
        The girlies on standby waving just to say hi\n\
        Did you stop? No, I just drove by";

    assert_eq!(String::from_utf8_lossy(&plaintext).trim(), expected);
}
