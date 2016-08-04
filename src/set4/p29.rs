use rand::{Rng, weak_rng};
use rust_crypto::digest::Digest;

use sha1::{Sha1, Sha1State};
use util::{read_u32v_be, write_u64_be};

fn mac_validation_oracle(key: &[u8], msg: &[u8], mac: &[u8]) -> bool {
	let mut m = Sha1::new();
	m.input(key);
	m.input(msg);
    let mut out = [0_u8; 20];
    m.result(&mut out);
    &out == mac
}

#[test]
fn run() {
    println!("");

    let mut rng = weak_rng();
    let key: [u8; 16] = rng.gen();
    let msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    let mut m = Sha1::new();
    m.input(&key);
    m.input(msg.as_bytes());
    let mut mac = [0_u8; 20];
    m.result(&mut mac);

    // digest output and future starting state of our MAC forger
    let mut hv = [0_u32; 5];
    read_u32v_be(&mut hv, &mac);

    // pre-allocate some buffers
    let mut ml_bytes = [0_u8; 8];
    let mut pad = [0_u8; 72];
    let mut forged_mac = [0_u8; 20];

    let mut success = false;

    // guess keylen and then perform length extension attack to generate
    // malicious message with valid hidden-key MAC
    for keylen in 0..100 {
        let blocklen = (keylen + msg.len()) % 64;
        let len_bytes = keylen + msg.len();
        let processed_blocks = (len_bytes - blocklen + 64) as u64;
        let len: u64 = (len_bytes as u64) << 3;
        write_u64_be(&mut ml_bytes, len);

        // compute padding for original message and use it in our forged
        // message
        let mut zeros = (56 - (blocklen as i32) - 1) % 64;
        if zeros < 0 {
            zeros += 64;
        }
        let padlen = (zeros + 9) as usize;
        pad[0] = 0x80;
        for i in 1..padlen-8 {
            pad[i] = 0;
        }
        pad[padlen-8..padlen].copy_from_slice(&ml_bytes);

        // start a digest from the previous SHA1's final state and then
        // input our malicious string
        let mut m2 = Sha1::from_state(processed_blocks, Sha1State { state: hv.clone() });
        m2.input(";admin=true".as_bytes());
        m2.result(&mut forged_mac);

        let mut forged_msg = Vec::new();
        forged_msg.extend_from_slice(msg.as_bytes());
        forged_msg.extend_from_slice(&pad[0..padlen]);
        forged_msg.extend_from_slice(";admin=true".as_bytes());

        if mac_validation_oracle(&key, &forged_msg, &forged_mac) {
            success = true;
            break;
        }
    }

    assert!(success);
}
