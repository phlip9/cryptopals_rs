use num::{BigUint, Zero, FromPrimitive};
use rand::{Rng, weak_rng};
use rust_crypto::digest::Digest;
use ssl::crypto::symm::{self, encrypt, decrypt};

use math::ModExp;
use sha1::Sha1;

#[test]
fn run() {
    let mut rng = weak_rng();
    let mut p_bytes = [0_u8; 256];
    rng.fill_bytes(&mut p_bytes);
    let p = BigUint::from_bytes_le(&p_bytes);
    //let g = BigUint::from_u32(2).unwrap();

    // Alice
    
    let mut a_bytes = [0_u8; 256];
    rng.fill_bytes(&mut a_bytes);
    let a = BigUint::from_bytes_le(&a_bytes);
    //let A = g.modexp(&a, &p);

    // Bob
    
    let mut b_bytes = [0_u8; 256];
    rng.fill_bytes(&mut b_bytes);
    let b = BigUint::from_bytes_le(&b_bytes);
    //let B = g.modexp(&b, &p);

    // A->M : p, g, A
    // M->B : p, g, p
    
    let s_B = p.modexp(&b, &p);

    // B->M : p, g, B
    // M->A : p, g, p

    let s_A = p.modexp(&a, &p);

    // s = A^b mod p
    //   = B^a mod p
    //   = p^b mod p
    //   = p^a mod p
    //   = 0

    // A->M : c = E(k, iv, m)
    // M->B : c

    let mut m = Sha1::new();
    m.input(&s_A.to_bytes_le());
    let mut out = [0_u8; 20];
    m.result(&mut out);

    let iv: [u8; 16] = rng.gen();

    let ctxt = {
        let key_A = &out[0..16];

        let msg = b"DOS'T THOU JEER AND T-TAUNT ME IN THE TEETH?";
        encrypt(symm::Type::AES_128_CBC, key_A, &iv, msg)
    };

    // Bob
    
    m.reset();
    m.input(&s_B.to_bytes_le());
    m.result(&mut out);

    let msg_B = {
        let key_B = &out[0..16];
        decrypt(symm::Type::AES_128_CBC, key_B, &iv, &ctxt)
    };

    // Mallory

    m.reset();
    m.input(&BigUint::zero().to_bytes_le());
    m.result(&mut out);

    let msg_M = {
        let key_M = &out[0..16];
        decrypt(symm::Type::AES_128_CBC, key_M, &iv, &ctxt)
    };

    assert_eq!(&msg_B, &msg_M);
}
