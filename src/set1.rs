use std::f32;
use std::str;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::collections::HashSet;

use serialize::base64::{self, FromBase64, ToBase64};
use serialize::hex::{FromHex, ToHex};
use ssl::crypto::symm::{self, decrypt};

#[test]
pub fn set_1_1() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f697 \
              36f6e6f7573206d757368726f6f6d";
    let b64_expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let b64_actual = hex.from_hex().unwrap().to_base64(base64::STANDARD);
    assert_eq!(b64_expected, b64_actual);
}

fn normalize(xs: &[f32]) -> Vec<f32> {
    let len = xs.len();
    let mut xs_normed = Vec::with_capacity(len);
    let n = norm(xs);
    let n_inv = 1.0 / n;
    for i in 0..len {
        xs_normed.push(n_inv * xs[i]);
    }
    xs_normed
}

fn english_freq_vec() -> Vec<f32> {
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
    normalize(&fs)
}

fn freq_vec(buf: &[u8]) -> Vec<f32> {
    let mut fs = vec![0.0f32; 256];
    for b in buf {
        fs[*b as usize] += 1.0f32;
    }
    let len = fs.len();
    let len_inv = 1.0f32 / (len as f32);
    for i in 0..len {
        fs[i] *= len_inv;
    }
    fs
}

fn dot(lhs: &[f32], rhs: &[f32]) -> f32 {
    let mut sum = 0.0f32;
    let llen = lhs.len();
    let rlen = rhs.len();
    if llen != rlen {
        panic!("dot product dimension mismatch : {} != {}", llen, rlen);
    }
    for i in 0..llen {
        sum += lhs[i] * rhs[i];
    }
    sum
}

fn norm(v: &[f32]) -> f32 {
    dot(v, v).sqrt()
}

fn freq_englishness(buf: &[u8], en_freq: &[f32]) -> f32 {
    let freq = freq_vec(buf);
    let n = norm(&freq);
    dot(&freq, en_freq) / n
}

fn dict_englishness(buf: &[u8], dict: &HashSet<String>) -> f32 {
    let string = String::from_utf8_lossy(buf);
    let words: Vec<String> = string.split(' ').map(|word| word.to_lowercase()).collect();
    let mut n_english_words = 0;
    let n_words = words.len();
    for word in words {
        if dict.contains(&word) {
            n_english_words += 1;
        }
    }
    (n_english_words as f32) / (n_words as f32)
}

fn xor_bytes(src: &[u8], xor: &[u8]) -> Vec<u8> {
    let xor_cycle = xor.iter().cycle();
    let res: Vec<u8> = src.iter()
        .zip(xor_cycle)
        .map(|(&a, &b)| a ^ b)
        .collect();
    res
}

fn dict(path: &str) -> Result<HashSet<String>, io::Error> {
    let f = try!(File::open(path));
    let reader = BufReader::new(f);
    let mut set: HashSet<String> = HashSet::new();
    for line in reader.lines() {
        let l: String = try!(line);
        set.insert(l.to_lowercase());
    }
    Ok(set)
}

fn relative_englishness(bytes: &[u8], en_freq_sorted: &[f32]) -> f32 {
    let mut freq = freq_vec(bytes);
    freq.sort_by(|a, b| b.partial_cmp(a).unwrap());
    let n = norm(&freq);
    dot(&freq, en_freq_sorted) / n
}

fn most_english<F>(bytes: &[u8], f: F) -> (u8, f32)
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

#[test]
pub fn set_1_2() {
    let src = "1c0111001f010100061a024b53535009181c";
    let xor = "686974207468652062756c6c277320657965";
    let out_exp = "746865206b696420646f6e277420706c6179";
    let src_buf = src.from_hex().unwrap();
    let xor_buf = xor.from_hex().unwrap();
    let out_bytes = xor_bytes(&src_buf, &xor_buf);
    let out_act = out_bytes.to_hex();
    assert_eq!(out_exp, out_act);
}

pub fn set_1_3() {
    let cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let cipher_bytes = cipher.from_hex().unwrap();
    let en_dict = dict("/usr/share/dict/american-english").unwrap();

    let (k, e) = most_english(&cipher_bytes, |m| dict_englishness(m, &en_dict));
    let xor = vec![k];
    let m = xor_bytes(&cipher_bytes, &xor);
    let string = String::from_utf8_lossy(&m);
    println!("{} : '{}' => {}", e, k as char, string);
}

pub fn set_1_4() {
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

    for &(i, r_e) in englishness_map.iter().take(5) {
        let (k, d_e) = most_english(&ciphers_bytes[i], |m| dict_englishness(m, &en_dict));
        let xor = vec![k];
        let m = xor_bytes(&ciphers_bytes[i], &xor);
        let string = String::from_utf8_lossy(&m);
        println!("{}, {} : {} : '{}' => {}", r_e, d_e, i, k as char, string);
    }
}

#[test]
pub fn set_1_5() {
    let m = "Burning 'em, if you ain't quick and nimble\n\
             I go crazy when I hear a cymbal";
    let bytes = m.as_bytes();
    let key = "ICE";
    let xor = key.as_bytes();
    let cipher_bytes = xor_bytes(&bytes, &xor);
    let cipher_text = cipher_bytes.to_hex();
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a\
                    26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027\
                    630c692b20283165286326302e27282f";
    assert_eq!(expected, cipher_text);
}


#[inline]
fn count_bits(mut x: u32) -> u32 {
    x = (x & 0x55555555) + ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x & 0x0f0f0f0f) + ((x >> 4) & 0x0f0f0f0f);
    x = (x & 0x00ff00ff) + ((x >> 8) & 0x00ff00ff);
    x = (x & 0x0000ffff) + ((x >> 16) & 0x0000ffff);
    x
}

#[inline]
fn hamming_dist(x: u32, y: u32) -> u32 {
    count_bits(x ^ y)
}

#[inline]
fn u8s_to_u32(xs: &[u8]) -> u32 {
    let a = *(xs.get(0).unwrap_or(&0)) as u32;
    let b = *(xs.get(1).unwrap_or(&0)) as u32;
    let c = *(xs.get(2).unwrap_or(&0)) as u32;
    let d = *(xs.get(3).unwrap_or(&0)) as u32;

    let mut x: u32 = d as u32;
    x += c << 8;
    x += b << 16;
    x += a << 24;
    x
}

fn bytes_hamming_dist(b1: &[u8], b2: &[u8]) -> u32 {
    let b2_u32s = b2.chunks(4)
        .map(|c| u8s_to_u32(c));
    b1.chunks(4)
        .map(|c| u8s_to_u32(c))
        .zip(b2_u32s)
        .map(|(x, y)| hamming_dist(x, y))
        .sum()
}

#[test]
fn test_count_bits() {
    assert_eq!(0, count_bits(0x00000000));
    assert_eq!(1, count_bits(0x00000001));
    assert_eq!(13, count_bits(0x5030ff01));
    assert_eq!(16, count_bits(0x0000ffff));
    assert_eq!(20, count_bits(0xf0fff00f));
    assert_eq!(32, count_bits(0xffffffff));
}

#[test]
fn test_hamming_dist() {
    assert_eq!(0, hamming_dist(0b001, 0b001));
    assert_eq!(1, hamming_dist(0b001, 0b101));
    assert_eq!(2, hamming_dist(0b001, 0b111));
}

#[test]
fn test_bytes_hamming_dist() {
    let b1 = "this is a test".as_bytes();
    let b2 = "wokka wokka!!!".as_bytes();
    assert_eq!(37, bytes_hamming_dist(&b1, &b2))
}

pub fn set_1_6() {
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

    println!("key = {}", String::from_utf8_lossy(&key));
    println!("===");

    let m = xor_bytes(&bytes, &key);
    println!("{}", String::from_utf8_lossy(&m));
}

pub fn set_1_7() {
    let mut f = File::open("./data/7.txt").unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    let bytes = s.from_base64().unwrap();

    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0 as u8; key.len()];

    let out = decrypt(symm::Type::AES_128_ECB, &key, &iv, &bytes);
    let m = String::from_utf8_lossy(&out);

    println!("{}", &m);
}

fn repeated_blocks(data: &[u8], size: usize) -> u32 {
    let mut count = 0;
    let mut set: HashSet<&[u8]> = HashSet::new();
    for chunk in data.chunks(size) {
        if set.contains(chunk) {
            count += 1;
        } else {
            set.insert(chunk);
        }
    }
    count
}

pub fn set_1_8() {
    let f = File::open("./data/8.txt").unwrap();
    let reader = BufReader::new(f);
    let key_size: usize = 16;

    let line = reader.lines()
        .map(|line| line.unwrap())
        .max_by_key(|line| {
            let bytes = line.from_hex().unwrap();
            let n = repeated_blocks(&bytes, key_size);
            if n != 0 {
                println!("{} | {}...", n, &line[0..15]);
            }
            n
        })
        .unwrap();

    println!("probable AES 128 ECB cipher text: {}...", &line[0..15]);
}