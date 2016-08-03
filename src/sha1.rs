use std::cmp;

use rust_crypto::digest::Digest;

use util::{read_u32v_be, write_u32v_be, write_u64_be};

#[derive(Copy, Clone)]
pub struct Sha1 {
    len: u64,
    blocks: Blocks,
    state: Sha1State,
}

#[derive(Copy, Clone)]
struct Sha1State {
    state: [u32; 5],
}

#[derive(Copy)]
struct Blocks {
    block: [u8; 64],
    len: u32,
}

const DEFAULT_STATE: Sha1State = Sha1State {
    state: [0x67452301_u32, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
};

impl Sha1 {
    pub fn new() -> Sha1 {
        Sha1 {
            len: 0,
            state: DEFAULT_STATE,
            blocks: Blocks {
                len: 0,
                block: [0; 64],
            },
        }
    }
}

impl Digest for Sha1 {
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
        write_u64_be(&mut ml_bytes, bits);
        let blocklen = self.blocks.len as usize;

        if blocklen < 56 {
            let mut last = [0_u8; 64];
            last[..blocklen].clone_from_slice(&self.blocks.block[..blocklen]);
            last[blocklen] = 0x80;
            last[56..64].clone_from_slice(&ml_bytes);
            state.process(&last[0..64]);
        } else {
            let mut last = [0_u8; 128];
            last[..blocklen].clone_from_slice(&self.blocks.block[..blocklen]);
            last[blocklen] = 0x80;
            last[120..128].clone_from_slice(&ml_bytes);
            state.process(&last[0..64]);
            state.process(&last[64..128]);
        }

        write_u32v_be(out, &state.state);
    }

    fn reset(&mut self) {
        self.state = DEFAULT_STATE;
        self.len = 0;
        self.blocks.len = 0;
    }

    fn output_bits(&self) -> usize { 160 }
    fn output_bytes(&self) -> usize { 20 }
    fn block_size(&self) -> usize { 64 }
}

impl Blocks {
    fn input<F>(&mut self, mut input: &[u8], mut f: F) where F: FnMut(&[u8]) {
        if self.len > 0 {
            let len = self.len as usize;
            let amt = cmp::min(input.len(), self.block.len() - len);
            self.block[len..len + amt].clone_from_slice(&input[..amt]);
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
                self.block[..chunk.len()].clone_from_slice(chunk);
                self.len = chunk.len() as u32;
            }
        }
    }
}

impl Sha1State {
    fn process(&mut self, block: &[u8]) {
        let mut w = [0u32; 80];
        read_u32v_be(&mut w[0..16], block);

        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in 0..20 {
            let t = a.rotate_left(5)
                .wrapping_add(d ^ (b & (c ^ d)))
                .wrapping_add(e)
                .wrapping_add(0x5a827999_u32)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for i in 20..40 {
            let t = a.rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(0x6ed9eba1_u32)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for i in 40..60 {
            let t = a.rotate_left(5)
                .wrapping_add((b & c) | (d & (b | c)))
                .wrapping_add(e)
                .wrapping_add(0x8f1bbcdc_u32)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for i in 60..80 {
            let t = a.rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(0xca62c1d6_u32)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl Clone for Blocks {
    fn clone(&self) -> Blocks {
        Blocks { ..*self }
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, weak_rng};

    use rust_crypto::digest::Digest;
    use rust_crypto::sha1::Sha1 as Sha1Ref;

    use super::Sha1;

    #[test]
    fn test_correctness() {
        let tests = [
            ("abc",
             "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
            ("The quick brown fox jumps over the lazy dog",
             "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            ("The quick brown fox jumps over the lazy cog",
             "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
            ("",
             "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ];

        let mut m = Sha1::new();

        for &(input, expected) in tests.iter() {
            m.input(input.as_bytes());
            assert_eq!(expected, m.result_str());
            m.reset();
        }
    }

    #[test]
    fn test_multiple_updates() {
        let mut m = Sha1::new();
        m.input("The quick brown ".as_bytes());
        m.input("fox jumps over ".as_bytes());
        m.input("the lazy dog".as_bytes());
        let expected = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
        assert_eq!(expected, m.result_str());
    }

    #[test]
    fn test_random() {
        let mut rng = weak_rng();
        let mut buf = [0_u8; 1024];
        let mut m_ref = Sha1Ref::new();
        let mut m = Sha1::new();
        for _ in 0..1000 {
            let len: usize = rng.gen_range(0, 1024);
            rng.fill_bytes(&mut buf[0..len]);
            m.input(&buf[0..len]);
            m_ref.input(&buf[0..len]);
            assert_eq!(m.result_str(), m_ref.result_str());
            m.reset();
            m_ref.reset();
        }
    }
}
