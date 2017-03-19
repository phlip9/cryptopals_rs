use std::cmp;

use rust_crypto::digest::Digest;

use util::{write_u64_le, write_u32v_le, read_u32v_le};

const DEFAULT_STATE: Md4State = Md4State {
    state: [0x67452301_u32, 0xefcdab89, 0x98badcfe, 0x10325476]
};

#[derive(Copy, Clone)]
pub struct Md4 {
    len: u64,
    blocks: Blocks,
    state: Md4State,
}

#[derive(Copy, Clone)]
pub struct Md4State {
    pub state: [u32; 4],
}

#[derive(Copy)]
struct Blocks {
    block: [u8; 64],
    len: u32,
}

impl Md4 {
    pub fn new() -> Md4 {
        Md4 {
            len: 0,
            state: DEFAULT_STATE,
            blocks: Blocks {
                len: 0,
                block: [0; 64],
            },
        }
    }

    pub fn from_state(len: u64, state: Md4State) -> Md4 {
        Md4 {
            len: len,
            state: state,
            blocks: Blocks {
                len: 0,
                block: [0; 64],
            }
        }
    }
}

impl Digest for Md4 {
    fn input(&mut self, data: &[u8]) {
        let len = &mut self.len;
        let state = &mut self.state;
        self.blocks.input(data, |chunk| {
            *len += 64;
            state.process(chunk);
        });
    }

    fn result(&mut self, out: &mut [u8]) {
        let mut state = self.state;
        let bits = (self.len + (self.blocks.len as u64)) << 3;
        let mut ml_bytes = [0_u8; 8];
        write_u64_le(&mut ml_bytes, bits);
        let blocklen = self.blocks.len as usize;

        if blocklen < 56 {
            self.len += 64;
            let mut last = [0_u8; 64];
            last[0..blocklen].copy_from_slice(&self.blocks.block[0..blocklen]);
            last[blocklen] = 0x80;
            last[56..64].copy_from_slice(&ml_bytes);
            state.process(&last[0..64]);
        } else {
            self.len += 128;
            let mut last = [0_u8; 128];
            last[0..blocklen].copy_from_slice(&self.blocks.block[0..blocklen]);
            last[blocklen] = 0x80;
            last[120..128].copy_from_slice(&ml_bytes);
            state.process(&last[0..64]);
            state.process(&last[64..128]);
        }

        write_u32v_le(out, &state.state);
    }

    fn reset(&mut self) {
        self.state = DEFAULT_STATE;
        self.len = 0;
        self.blocks.len = 0;
    }

    fn output_bits(&self) -> usize { 128 }
    fn output_bytes(&self) -> usize { 16 }
    fn block_size(&self) -> usize { 64 }
}

impl Blocks {
    fn input<F>(&mut self, mut input: &[u8], mut f: F) where F: FnMut(&[u8]) {
        if self.len > 0 {
            let len = self.len as usize;
            let amt = cmp::min(input.len(), self.block.len() - len);
            self.block[len..len + amt].copy_from_slice(&input[..amt]);
            if len + amt == self.block.len() {
                f(&self.block);
                self.len = 0;
                input = &input[amt..];
            } else {
                self.len += amt as u32;
                return
            }
        }
        assert_eq!(self.len, 0);
        for chunk in input.chunks(64) {
            if chunk.len() == 64 {
                f(chunk);
            } else {
                self.block[..chunk.len()].copy_from_slice(chunk);
                self.len = chunk.len() as u32;
            }
        }
    }
}

impl Md4State {
    fn process(&mut self, block: &[u8]) {
        fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }
        fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }
        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }
        fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(f(b, c, d))
                .wrapping_add(k)
                .rotate_left(s)
        }
        fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(g(b, c, d))
                .wrapping_add(k)
                .wrapping_add(0x5a827999_u32)
                .rotate_left(s)
        }
        fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(h(b, c, d))
                .wrapping_add(k)
                .wrapping_add(0x6ed9eba1_u32)
                .rotate_left(s)
        }

        let mut w = [0u32; 16];
        read_u32v_le(&mut w, block);

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        for i in 0..4 {
            let j = i * 4;
            a = op1(a, b, c, d, w[j    ], 3);
            d = op1(d, a, b, c, w[j + 1], 7);
            c = op1(c, d, a, b, w[j + 2], 11);
            b = op1(b, c, d, a, w[j + 3], 19);
        }

        for i in 0..4 {
            a = op2(a, b, c, d, w[i    ], 3);
            d = op2(d, a, b, c, w[i + 4], 5);
            c = op2(c, d, a, b, w[i + 8], 9);
            b = op2(b, c, d, a, w[i + 12], 13);
        }

        for &i in [0, 2, 1, 3].iter() {
            a = op3(a, b, c, d, w[i    ], 3);
            d = op3(d, a, b, c, w[i + 8], 9);
            c = op3(c, d, a, b, w[i + 4], 11);
            b = op3(b, c, d, a, w[i + 12], 15);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

impl Clone for Blocks {
    fn clone(&self) -> Blocks {
        Blocks { ..*self }
    }
}

#[cfg(test)]
mod tests {
    use rust_crypto::digest::Digest;
    use super::Md4;

    #[test]
    fn test_correctness() {
        let tests = [
            ("",
             "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a",
             "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc",
             "a448017aaf21d8525fc10ae87aa6729d"),
            ("abcdefghijklmnopqrstuvwxyz",
             "d79e1c308aa5bbcdeea8ed63df412da9"),
            ("message digest",
             "d9130a8164549fe818874806e1c7014b"),
        ];

        let mut m = Md4::new();

        for &(input, expected) in tests.iter() {
            m.input(input.as_bytes());
            assert_eq!(expected, m.result_str());
            m.reset();
        }
    }
}
