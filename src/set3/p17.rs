use rand::{Rng, weak_rng};
use serialize::base64::{FromBase64};
use ssl::crypto::symm::{self, encrypt, Crypter};

use crypto::pkcs7;

fn decryption_oracle(key: &[u8], iv: &[u8], ctxt: &[u8]) -> bool {
    let c = Crypter::new(symm::Type::AES_128_CBC);
    c.init(symm::Mode::Decrypt, &key, &iv);
    // handle padding manually
    c.pad(false);
    let mut r = c.update(&ctxt);
    let rest = c.finalize();
    r.extend(rest.into_iter());
    pkcs7::unpad(r).is_some()
}

fn padding_attack(key: &[u8], iv: &[u8], ctxt: &[u8]) -> Vec<u8> {
    let mut ptxt = Vec::with_capacity(ctxt.len());

    let blocks = ctxt.len() / 16;
    for b in 0..blocks {
        let cb_view = if b == 0 {
            &iv
        } else {
            &ctxt[(b-1)*16..b*16]
        };
        let mut cb = cb_view.to_vec();
        let mut pb = [0_u8; 16];
        let c_i = &ctxt[b*16..(b+1)*16];
        for i in 0..16 {
            let pad = (i + 1) as u8;
            let j = 16 - i - 1;

            for k in (j+1)..16 {
                cb[k] = cb_view[k] ^ pb[k] ^ pad;
            }

            for c in 0...255 {
                if c == pad {
                    continue;
                }
                cb[j] = cb_view[j] ^ c ^ pad;
                if decryption_oracle(&key, &cb, &c_i) {
                    pb[j] = c;
                    break;
                }
                if c == 255 {
                    pb[j] = pad;
                }
            }
        }
        ptxt.extend_from_slice(&pb);
    }
    pkcs7::unpad(ptxt).unwrap()
}

#[test]
fn run() {
    let unknowns: Vec<Vec<u8>> = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ].iter().map(|s| s.from_base64().unwrap()).collect::<Vec<_>>();

    let mut rng = weak_rng();
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);
    let mut iv = [0_u8; 16];
    rng.fill_bytes(&mut iv);

    println!("");
    for i in 0..unknowns.len() {
        let unknown = &unknowns[i];
        let ctxt = encrypt(symm::Type::AES_128_CBC, &key, &iv, unknown);
        let ptxt = padding_attack(&key, &iv, &ctxt);
        println!("{}", &String::from_utf8_lossy(&ptxt));
        assert_eq!(unknown, &ptxt);
    }
}
