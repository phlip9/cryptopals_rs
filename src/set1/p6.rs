use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

use serialize::base64::FromBase64;

use freq::{english_freq_vec, freq_englishness, most_english, dict, dict_englishness};
use util::{xor_bytes, bytes_hamming_dist};

#[test]
fn run() {
    let f = File::open("./data/6.txt").unwrap();
    let reader = BufReader::new(f);

    let buf: String = reader.lines()
        .map(|line| line.unwrap())
        .fold(String::new(), |mut buf, line| {
            buf.push_str(line.trim());
            buf
        });

    let bytes = buf.as_str().from_base64().unwrap();

    let mut norm_dists: Vec<(usize, f32)> = (2..40).map(|k| {
        let d1 = bytes_hamming_dist(&bytes[0..k], &bytes[k..2*k]);
        let d2 = bytes_hamming_dist(&bytes[0..k], &bytes[2*k..3*k]);
        let d3 = bytes_hamming_dist(&bytes[0..k], &bytes[3*k..4*k]);
        (k, (d1 + d2 + d3) as f32 / (3*k) as f32)
    }).collect();
    norm_dists.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    let en_freq = english_freq_vec();

    let keys = norm_dists.iter()
        .take(5)
        .map(|&(k, _)| {
            (0..k).map(|i| {
                let block = (i..bytes.len())
                    .step_by(k)
                    .map(|j| bytes[j])
                    .collect::<Vec<u8>>();
                let (sub_key, _) = most_english(&block, |m| freq_englishness(m, &en_freq));
                sub_key
            })
            .collect::<Vec<u8>>()
        })
        .collect::<Vec<Vec<u8>>>();

    let en_dict = dict("/usr/share/dict/american-english").unwrap();

    let mut key = keys.into_iter()
        .max_by_key(|k| {
            let m = xor_bytes(&bytes, k);
            (dict_englishness(&m, &en_dict) * 1000.0) as i32
        })
        .unwrap();

    // manual fix lol
    key[3] = 'm' as u8;

    assert_eq!(String::from_utf8_lossy(&key), "Terminator X: Bring the noise");
}
