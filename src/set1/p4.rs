use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

use serialize::hex::FromHex;

use freq::{english_freq_vec, dict, dict_englishness, relative_englishness, most_english};
use util::xor_bytes;

#[test]
fn run() {
    let mut en_freq_sorted = english_freq_vec();
    en_freq_sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());

    let f = File::open("./data/4.txt").unwrap();
    let reader = BufReader::new(f);

    let ciphers_bytes: Vec<Vec<u8>> = reader.lines()
        .map(|line| line.unwrap().from_hex().unwrap())
        .collect();

    let mut englishness_map: Vec<(usize, f32)> = ciphers_bytes.iter()
        .enumerate()
        .map(|(i, bytes)| (i, relative_englishness(bytes, &en_freq_sorted)))
        .collect();

    englishness_map.sort_by(|a, b| b.1.partial_cmp(&(a.1)).unwrap());

    let en_dict = dict("/usr/share/dict/american-english").unwrap();

    let (i, k, _) = englishness_map.iter()
        .take(5)
        .map(|&(i, _)| {
            let (k, d_e) = most_english(&ciphers_bytes[i], |m| dict_englishness(m, &en_dict));
            (i, k, d_e)
        })
        .max_by_key(|&(_, _, d_e)| (d_e * 100000.0) as i32)
        .unwrap();

    let xor = vec![k];
    let m = xor_bytes(&ciphers_bytes[i], &xor);
    let string = String::from_utf8_lossy(&m);
    assert_eq!("Now that the party is jumping", string.trim());
}
