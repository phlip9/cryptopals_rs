use num::{BigUint, Zero, FromPrimitive};
use rand::{Rng, weak_rng};
use rust_crypto::digest::Digest;
use ssl::symm::{self, encrypt, decrypt};

use math::ModExp;
use sha1::Sha1;

#[test]
fn run() {
    let mut rng = weak_rng();
    let p_bytes =
    b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
      e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
      3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
      6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
      24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
      c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
      bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
      fffffffffffff";
    let p = BigUint::from_bytes_le(p_bytes);
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
        encrypt(symm::Cipher::aes_128_cbc(), key_A, Some(&iv), msg).unwrap()
    };

    // Bob
    
    m.reset();
    m.input(&s_B.to_bytes_le());
    m.result(&mut out);

    let msg_B = {
        let key_B = &out[0..16];
        decrypt(symm::Cipher::aes_128_cbc(), key_B, Some(&iv), &ctxt).unwrap()
    };

    // Mallory

    m.reset();
    m.input(&BigUint::zero().to_bytes_le());
    m.result(&mut out);

    let msg_M = {
        let key_M = &out[0..16];
        decrypt(symm::Cipher::aes_128_cbc(), key_M, Some(&iv), &ctxt).unwrap()
    };

    assert_eq!(&msg_B, &msg_M);
}
