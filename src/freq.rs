use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::collections::HashSet;

use vector::{Vecf, Dot, Magnitude, Normalize};
use util::xor_bytes;

pub fn english_freq_vec() -> Vecf {
    let mut fs = vec![0.0f32; 256];
    fs['a' as usize] = 0.0651738;
    fs['b' as usize] = 0.0124248;
    fs['c' as usize] = 0.0217339;
    fs['d' as usize] = 0.0349835;
    fs['e' as usize] = 0.1041442;
    fs['f' as usize] = 0.0197881;
    fs['g' as usize] = 0.0158610;
    fs['h' as usize] = 0.0492888;
    fs['i' as usize] = 0.0558094;
    fs['j' as usize] = 0.0009033;
    fs['k' as usize] = 0.0050529;
    fs['l' as usize] = 0.0331490;
    fs['m' as usize] = 0.0202124;
    fs['n' as usize] = 0.0564513;
    fs['o' as usize] = 0.0596302;
    fs['p' as usize] = 0.0137645;
    fs['q' as usize] = 0.0008606;
    fs['r' as usize] = 0.0497563;
    fs['s' as usize] = 0.0515760;
    fs['t' as usize] = 0.0729357;
    fs['u' as usize] = 0.0225134;
    fs['v' as usize] = 0.0082903;
    fs['w' as usize] = 0.0171272;
    fs['x' as usize] = 0.0013692;
    fs['y' as usize] = 0.0145984;
    fs['z' as usize] = 0.0007836;
    fs[' ' as usize] = 0.1918182;

    for c in 'A' as usize .. ('Z' as usize + 1) {
        fs[c] = fs[c + 32] / 20.0f32;
    }

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
    (0..255+1)
        .map(|k_| {
            let k = k_ as u8;
            let xor = [k];
            let m = xor_bytes(bytes, &xor);
            (k, f(&m))
        })
        // hack to max by float key
        .max_by_key(|&(_, e)| (e * 1000.0) as i32)
        .map(|(k, e)| (k, e as f32 / 1000.0))
        .unwrap()
}
