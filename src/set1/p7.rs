use std::io::prelude::*;
use std::fs::File;

use ssl::symm::{self, decrypt};

use serialize::base64::FromBase64;

#[test]
fn run() {
    let mut f = File::open("./data/7.txt").unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    let bytes = s.from_base64().unwrap();

    let key = "YELLOW SUBMARINE".as_bytes();

    let out = decrypt(symm::Cipher::aes_128_ecb(), &key, None, &bytes).unwrap();
    let m = String::from_utf8_lossy(&out);

    assert!(m.starts_with("I'm back and I'm ringin' the bell"));
    assert!(m.trim().ends_with("Play that funky music"));
}
