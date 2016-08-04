use std::iter::FromIterator;
use std::num::Wrapping as w;
use std::mem;
use std::ptr;

use rand::{Rng, SeedableRng, Rand};

pub fn xor_bytes(src: &[u8], xor: &[u8]) -> Vec<u8> {
    let xor_cycle = xor.iter().cycle();
    let res: Vec<u8> = src.iter()
        .zip(xor_cycle)
        .map(|(&a, &b)| a ^ b)
        .collect();
    res
}

// pretty naive divide and conquor bit counting
pub fn count_bits(mut x: u32) -> u32 {
    x = (x & 0x55555555) + ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x & 0x0f0f0f0f) + ((x >> 4) & 0x0f0f0f0f);
    x = (x & 0x00ff00ff) + ((x >> 8) & 0x00ff00ff);
    x = (x & 0x0000ffff) + ((x >> 16) & 0x0000ffff);
    x
}

pub fn hamming_dist(x: u32, y: u32) -> u32 {
    count_bits(x ^ y)
}

pub fn u8s_to_u32(xs: &[u8]) -> u32 {
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

pub fn bytes_hamming_dist(b1: &[u8], b2: &[u8]) -> u32 {
    let b2_u32s = b2.chunks(4)
        .map(|c| u8s_to_u32(c));
    b1.chunks(4)
        .map(|c| u8s_to_u32(c))
        .zip(b2_u32s)
        .map(|(x, y)| hamming_dist(x, y))
        .sum()
}

pub fn hexdump(b: &[u8]) {
    for bytes in b.chunks(16) {
        let hex_digits =  bytes.iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<_>>()
            .join(" ");
        let string = bytes.iter()
            .map(|&c| {
                if c >= 32 && c < 127 {
                    format!("{}", c as char)
                } else {
                    ".".to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("");
        print!("{} ", hex_digits);
        if bytes.len() != 16 {
            let padding = String::from_iter(vec![' '; 3 * (16 - bytes.len())]);
            print!("{}", &padding);
        }
        println!("{}", string);
    }
}

#[allow(bad_style)]
pub type w32 = w<u32>;

// Mersenne Twister 19937 Constants
const MW: usize = 32;
const MU: usize = 11;
const MS: usize = 7;
const ML: usize = 18;
const MT: usize = 15;
const MN: usize = 624;
const MM: usize = 397;
const M1: w32 = w(0x1_u32);
const MA: w32 = w(0x9908B0DF_u32);
const MB: w32 = w(0x9D2C5680_u32);
const MC: w32 = w(0xEFC60000_u32);
const MF: w32 = w(0x6C078965_u32);
const MPU: w32 = w(0x80000000_u32);
const MPL: w32 = w(0x7fffffff_u32);

#[allow(bad_style)]
pub struct MT19937Rng {
    i: usize,
    X: [w32; MN],
}

impl MT19937Rng {
    pub fn new_unseeded() -> MT19937Rng {
        let mut rng = MT19937Rng {
            i: MN,
            X: [w(0_u32); MN]
        };
        rng.reseed(5489);
        rng
    }

    #[allow(bad_style)]
    pub fn from_state(i: usize, X: [w32; MN]) -> MT19937Rng {
        MT19937Rng {
            i: i,
            X: X,
        }
    }

    #[allow(bad_style)]
    fn twist(&mut self) {
        for j in 0..MN {
            let x = (self.X[j] & MPU) +
                (self.X[(j + 1) % MN] & MPL);
            let xA = (x >> 1) ^ (MA * (x & M1));
            self.X[j] = self.X[(j + MM) % MN] ^ xA;
        }
        self.i = 0;
    }
}

impl SeedableRng<u32> for MT19937Rng {
    fn reseed(&mut self, seed: u32) {
        self.i = MN;
        self.X[0] = w(seed);
        for j in 1..MN {
            let x_p = self.X[j - 1];
            self.X[j] = MF * (x_p ^ (x_p >> (MW - 2))) + w(j as u32);
        }
    }

    fn from_seed(seed: u32) -> MT19937Rng {
        let mut rng = MT19937Rng::new_unseeded();
        rng.reseed(seed);
        rng
    }
} 

impl Rng for MT19937Rng {
    fn next_u32(&mut self) -> u32 {
        if self.i >= MN {
            self.twist();
        }

        let mut y = self.X[self.i];
        y = y ^ (y >> MU);
        y = y ^ ((y << MS) & MB);
        y = y ^ ((y << MT) & MC);
        y = y ^ (y >> ML);

        self.i += 1;
        y.0
    }
}

impl Rand for MT19937Rng {
    fn rand<R: Rng>(rng: &mut R) -> MT19937Rng {
        let seed: u32 = rng.gen();
        MT19937Rng::from_seed(seed)
    }
}

pub struct PRNGKeystream<'a, R: 'a> {
    rng: &'a mut R,
    curr: u32,
    i: usize,
}

impl<'a, R: Rng> PRNGKeystream<'a, R> {
    fn from_rng(rng: &'a mut R) -> PRNGKeystream<'a, R> {
        let curr = rng.next_u32();
        PRNGKeystream {
            rng: rng,
            curr: curr,
            i: 0,
        }
    }
}

impl<'a, R: Rng> Iterator for PRNGKeystream<'a, R> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.i == 4 {
            self.curr = self.rng.next_u32();
            self.i = 0;
        }
        let sh = self.i << 3;
        let out = ((self.curr & (0xFF << sh)) >> sh) as u8;
        self.i += 1;
        Some(out)
    }
}

pub fn prng_crypt<R: Rng>(rng: &mut R, data: &[u8]) -> Vec<u8> {
    let ks = PRNGKeystream::from_rng(rng);
    ks.zip(data)
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>()
}

pub fn read_u32_be(input: &[u8]) -> u32 {
    assert!(input.len() == 4);
    unsafe {
        let mut tmp: u32 = mem::uninitialized();
        ptr::copy_nonoverlapping(
            input.get_unchecked(0),
            &mut tmp as *mut _ as *mut u8,
            4);
        u32::from_be(tmp)
    }
}

pub fn read_u32_le(input: &[u8]) -> u32 {
    assert!(input.len() == 4);
    unsafe {
        let mut tmp: u32 = mem::uninitialized();
        ptr::copy_nonoverlapping(
            input.get_unchecked(0),
            &mut tmp as *mut _ as *mut u8,
            4);
        u32::from_le(tmp)
    }
}

pub fn read_u64_be(input: &[u8]) -> u64 {
    assert!(input.len() == 8);
    unsafe {
        let mut tmp: u64 = mem::uninitialized();
        ptr::copy_nonoverlapping(
            input.get_unchecked(0),
            &mut tmp as *mut _ as *mut u8,
            8);
        u64::from_be(tmp)
    }
}

pub fn read_u64_le(input: &[u8]) -> u64 {
    assert!(input.len() == 8);
    unsafe {
        let mut tmp: u64 = mem::uninitialized();
        ptr::copy_nonoverlapping(
            input.get_unchecked(0),
            &mut tmp as *mut _ as *mut u8,
            8);
        u64::from_le(tmp)
    }
}

pub fn read_u32v_be(dst: &mut [u32], input: &[u8]) {
    assert!(dst.len() * 4 == input.len());
    unsafe {
        let mut x: *mut u32 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: u32 = mem::uninitialized();
            ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 4);
            *x = u32::from_be(tmp);
            x = x.offset(1);
            y = y.offset(4);
        }
    }
}

pub fn read_u32v_le(dst: &mut [u32], input: &[u8]) {
    assert!(dst.len() * 4 == input.len());
    unsafe {
        let mut x: *mut u32 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: u32 = mem::uninitialized();
            ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 4);
            *x = u32::from_le(tmp);
            x = x.offset(1);
            y = y.offset(4);
        }
    }
}

pub fn write_u32_be(dst: &mut [u8], mut input: u32) {
    assert!(dst.len() == 4);
    input = input.to_be();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 4);
    }
}

pub fn write_u32_le(dst: &mut [u8], mut input: u32) {
    assert!(dst.len() == 4);
    input = input.to_le();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 4);
    }
}

pub fn write_u64_be(dst: &mut [u8], mut input: u64) {
    assert!(dst.len() == 8);
    input = input.to_be();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 8);
    }
}

pub fn write_u64_le(dst: &mut [u8], mut input: u64) {
    assert!(dst.len() == 8);
    input = input.to_le();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 8);
    }
}

pub fn write_u32v_be(dst: &mut [u8], input: &[u32]) {
    assert!(dst.len() == 4*input.len());
    unsafe {
        let mut x: *mut u8 = dst.get_unchecked_mut(0);
        let mut y: *const u32 = input.get_unchecked(0);
        for _ in 0..input.len() {
            let tmp = (*y).to_be();
            ptr::copy_nonoverlapping(&tmp as *const u32, x as *mut u32, 1);
            x = x.offset(4);
            y = y.offset(1);
        }
    }
}

pub fn write_u32v_le(dst: &mut [u8], input: &[u32]) {
    assert!(dst.len() == 4*input.len());
    unsafe {
        let mut x: *mut u8 = dst.get_unchecked_mut(0);
        let mut y: *const u32 = input.get_unchecked(0);
        for _ in 0..input.len() {
            let tmp = (*y).to_le();
            ptr::copy_nonoverlapping(&tmp as *const u32, x as *mut u32, 1);
            x = x.offset(4);
            y = y.offset(1);
        }
    }
}

#[test]
fn test_read_u32() {
    let input = [0x12_u8, 0x34, 0x56, 0x78];
    assert_eq!(0x12345678_u32, read_u32_be(&input));
    assert_eq!(0x78563412_u32, read_u32_le(&input));
}

#[test]
fn test_read_u64() {
    let input = [
        0x12_u8, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef,
    ];
    assert_eq!(0x1234567890abcdef_u64, read_u64_be(&input));
    assert_eq!(0xefcdab9078563412_u64, read_u64_le(&input));
}

#[test]
fn test_read_u32v() {
    let input = [
        0x12_u8, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef,
    ];
    let mut dst = [0_u32; 2];
    read_u32v_be(&mut dst, &input);
    assert_eq!(dst[0], 0x12345678_u32);
    assert_eq!(dst[1], 0x90abcdef_u32);
    read_u32v_le(&mut dst, &input);
    assert_eq!(dst[0], 0x78563412_u32);
    assert_eq!(dst[1], 0xefcdab90_u32);
}

#[test]
fn test_write_u32() {
    let mut dst = [0_u8; 4];
    write_u32_be(&mut dst, 0x12345678_u32);
    assert_eq!(read_u32_be(&dst), 0x12345678_u32);
    write_u32_le(&mut dst, 0x12345678_u32);
    assert_eq!(read_u32_le(&dst), 0x12345678_u32);
}

#[test]
fn test_write_u64() {
    let mut dst = [0_u8; 8];
    write_u64_be(&mut dst, 0x1234567890abcdef_u64);
    assert_eq!(read_u64_be(&dst), 0x1234567890abcdef_u64);
    write_u64_le(&mut dst, 0x1234567890abcdef_u64);
    assert_eq!(read_u64_le(&dst), 0x1234567890abcdef_u64);
}

#[test]
fn test_write_u32v() {
    let mut dst = [0_u8; 8];
    let src = [0x12345678_u32, 0x90abcdef_u32];
    write_u32v_be(&mut dst, &src);
    assert_eq!(&dst, &[0x12_u8,0x34,0x56,0x78,0x90,0xab,0xcd,0xef]);
    write_u32v_le(&mut dst, &src);
    assert_eq!(&dst, &[0x78_u8,0x56,0x34,0x12,0xef,0xcd,0xab,0x90]);
}

#[test]
fn test_prng_crypt() {
    let mut ks_rng = MT19937Rng::from_seed(0x12345678_u32);
    let data = "DOS'T THOU JEER AND T-TAUNT ME IN THE TEETH?".as_bytes();
    let ctxt = prng_crypt(&mut ks_rng, data);

    ks_rng.reseed(0x12345678_u32);
    let ptxt = prng_crypt(&mut ks_rng, &ctxt);
    assert_eq!(ptxt.as_slice(), data);
}

#[test]
fn test_prng_keystream() {
    let mut ks_rng = MT19937Rng::from_seed(0x12345678_u32);
    let mut ref_rng = MT19937Rng::from_seed(0x12345678_u32);
    let ks = PRNGKeystream::from_rng(&mut ks_rng);

    let n = 1000;

    let ref_outs = (0..n)
        .map(|_| ref_rng.next_u32());

    let ks_outs = ks
        .take(4*n)
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| [c[0], c[1], c[2], c[3]])
        .map(|c| unsafe { mem::transmute_copy(&c) })
        .collect::<Vec<_>>();

    for (ref_u32, ks_u32) in ref_outs.zip(ks_outs) {
        assert_eq!(ref_u32, ks_u32);
    }
}

#[test]
fn test_xor_bytes() {
    assert_eq!(
        xor_bytes(&[0x12, 0x34], &[0xfe, 0xdc]),
        &[0x12 ^ 0xfe, 0x34 ^ 0xdc]);
    assert_eq!(
        xor_bytes(&[0x12, 0x34], &[0x12, 0x34]),
        &[0x00, 0x00]);
    assert_eq!(
        xor_bytes(&[0x12, 0x34], &[0x7e]),
        &[0x12 ^ 0x7e, 0x34 ^ 0x7e]);
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

