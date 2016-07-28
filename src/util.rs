use std::iter::FromIterator;

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

