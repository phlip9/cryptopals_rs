use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

use rand::{Rng, weak_rng};
use serialize::base64::{FromBase64};

use crypto::aes;
use freq::{english_freq_vec, freq_englishness, most_english};
use util::{hexdump, xor_bytes};

#[test]
fn run() {
    let mut rng = weak_rng();
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);
    let nonce: u64 = rng.gen();

    let ctxts = File::open("./data/19.txt")
        .map(|f| BufReader::new(f).lines())
        .unwrap()
        .map(|line| line.unwrap().from_base64().unwrap())
        .map(|line| aes::ctr(&key, nonce, &line))
        .collect::<Vec<_>>();

    let max_ctxt_len = ctxts.iter()
        .map(|ctx| ctx.len())
        .max()
        .unwrap_or(0);

    let column_bytes = (0..max_ctxt_len)
        .map(|i| {
            ctxts.iter()
                .filter_map(|ctxt| ctxt.get(i).map(|c| *c))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let en_freq = english_freq_vec();

    let recovered_key = (0..max_ctxt_len)
        .map(|i| {
            most_english(&column_bytes[i], |m| {
                for &c in m.iter() {
                    match c as char {
                        ' ' | '!' | '"' | ',' | '-' | '.' | ':' | ';' | '?' | '\''
                            | 'a'...'z' | 'A'...'Z'  => (),
                        _ => {
                            return 0.0;
                        }
                    }
                }
                freq_englishness(&m, &en_freq)
            }).0
        })
        .collect::<Vec<u8>>();

    println!("ptxt:");
    for ctxt in ctxts.iter() {
        let ptxt = xor_bytes(ctxt, &recovered_key);
        println!("");
        hexdump(&ptxt);
    }
}
