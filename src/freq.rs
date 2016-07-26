use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::collections::HashSet;

use vector::{Vecf, Dot, Magnitude, Normalize};
use util::xor_bytes;

pub fn english_freq_vec() -> Vecf {
    let mut fs = vec![0.0f32; 256];
    fs['a' as usize] = 0.08167;
    fs['b' as usize] = 0.01492;
    fs['c' as usize] = 0.02782;
    fs['d' as usize] = 0.04253;
    fs['e' as usize] = 0.12702;
    fs['f' as usize] = 0.02228;
    fs['g' as usize] = 0.02015;
    fs['h' as usize] = 0.06094;
    fs['i' as usize] = 0.06966;
    fs['j' as usize] = 0.00153;
    fs['k' as usize] = 0.00772;
    fs['l' as usize] = 0.04025;
    fs['m' as usize] = 0.02406;
    fs['n' as usize] = 0.06749;
    fs['o' as usize] = 0.07507;
    fs['p' as usize] = 0.01929;
    fs['q' as usize] = 0.00095;
    fs['r' as usize] = 0.05987;
    fs['s' as usize] = 0.06327;
    fs['t' as usize] = 0.09056;
    fs['u' as usize] = 0.02758;
    fs['v' as usize] = 0.00978;
    fs['w' as usize] = 0.02361;
    fs['x' as usize] = 0.00150;
    fs['y' as usize] = 0.01974;
    fs['z' as usize] = 0.00074;
    fs.norm()
}

pub fn freq_vec(buf: &[u8]) -> Vecf {
    let mut fs = vec![0.0f32; 256];
    for b in buf {
        fs[*b as usize] += 1.0f32;
    }
    fs.norm()
}

pub fn freq_englishness(buf: &[u8], en_freq: &Vecf) -> f32 {
    let freq = freq_vec(buf);
    // assumes other frequency vector already normalized
    freq.dot(en_freq).unwrap() / freq.mag()
}

pub fn dict_englishness(buf: &[u8], dict: &HashSet<String>) -> f32 {
    let string = String::from_utf8_lossy(buf);
    let words = string
        .replace(|c| c == ',' || c == '.' || c == '!' ||
                 c == '?' || c == '&',
                 "")
        .split(' ')
        .map(|word| word.to_lowercase())
        .collect::<Vec<_>>();
    let mut n_english_words = 0;
    let n_words = words.len();
    for word in words {
        if dict.contains(&word) {
            n_english_words += 1;
        }
    }
    (n_english_words as f32) / (n_words as f32)
}

pub fn dict(path: &str) -> Result<HashSet<String>, io::Error> {
    let f = try!(File::open(path));
    let reader = BufReader::new(f);
    let mut set: HashSet<String> = HashSet::new();
    for line in reader.lines() {
        let l: String = try!(line);
        set.insert(l.to_lowercase());
    }
    Ok(set)
}

pub fn relative_englishness(bytes: &[u8], en_freq_sorted: &Vecf) -> f32 {
    let mut freq = freq_vec(bytes);
    freq.sort_by(|a, b| b.partial_cmp(a).unwrap());
    freq.dot(en_freq_sorted).unwrap() / freq.mag()
}

pub fn most_english<F>(bytes: &[u8], f: F) -> (u8, f32)
    where F: Fn(&[u8]) -> f32
{
    (0...255)
        .map(|k| {
            let xor = vec![k];
            let m = xor_bytes(bytes, &xor);
            (k, f(&m))
        })
        .max_by_key(|&(_, e)| (e * 1000.0) as i32)
        .map(|(k, e)| (k, e as f32 / 1000.0))
        .unwrap()
}
