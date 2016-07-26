use rand::{Rng, weak_rng};
use serialize::base64::FromBase64;
use ssl::crypto::symm::{self, encrypt};

fn encryption_oracle(input: &[u8], unknown: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = [0_u8; 16];

    let mut data: Vec<u8> = Vec::with_capacity(input.len() + unknown.len());
    data.extend_from_slice(input);
    data.extend_from_slice(unknown);

    encrypt(symm::Type::AES_128_ECB, key, &iv, &data)
}

#[test]
fn run() {
    // unknown text we will attempt to decode with attacker controlled input
    // to the encryption oracle
    let unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                   YnkK".from_base64().unwrap();
    let mut rng = weak_rng();
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);

    // Determine blocksize
    let mut i = 1;
    let blocksize;
    loop {
        let input = vec!['A' as u8; 2*i];
        let out = encryption_oracle(&input, &unknown, &key);

        let block1 = &out[0..i];
        let block2 = &out[i..2*i];
        if block1 == block2 {
            blocksize = i;
            break;
        }
        i += 1;
    }

    // Determine ciphertext length
    let len = encryption_oracle("".as_bytes(), &unknown, &key).len();
    let mut ctxt_len = 0;
    for i in 1..blocksize+1 {
        let input = vec!['A' as u8; i];
        let new_len = encryption_oracle(&input, &unknown, &key).len();
        if new_len != len {
            ctxt_len = new_len - blocksize - i;
            break;
        }
    }

    println!("blocksize = {}", blocksize);
    println!("ciphertext length = {}", ctxt_len);

    // Decrypt ciphertext byte-by-byte
    let mut plaintext: Vec<u8> = Vec::with_capacity(ctxt_len);
    for i in 0..ctxt_len {
        let mut input: Vec<u8> = Vec::new();

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

        let out = encryption_oracle(&input, &unknown, &key);

        let b_i = (i / blocksize) + 256;
        let cipher_block = &out[b_i*blocksize..(b_i+1)*blocksize];

        // search for input block with same AES ECB output
        for char_guess in 0...255 {
            let j = char_guess as usize;
            let guess_block = &out[j*blocksize..(j+1)*blocksize];
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

