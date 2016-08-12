use num::{BigUint, Zero, One, FromPrimitive};
use rand::{Rng, weak_rng};
use rust_crypto::digest::Digest;
use ssl::crypto::symm::{self, encrypt, decrypt};

use math::ModExp;
use sha1::Sha1;

#[test]
fn run_g_1() {
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

    // g = 1 => s = 1
    let g = BigUint::from_u32(1).unwrap();

    // Alice
    
    let mut a_bytes = [0_u8; 256];
    rng.fill_bytes(&mut a_bytes);
    let a = BigUint::from_bytes_le(&a_bytes);
    let A = g.modexp(&a, &p);

    // Bob
    
    let mut b_bytes = [0_u8; 256];
    rng.fill_bytes(&mut b_bytes);
    let b = BigUint::from_bytes_le(&b_bytes);
    let B = g.modexp(&b, &p);

    // A->B : p, g, A
    let s_B = A.modexp(&b, &p);

    // B->A : p, g, B
    let s_A = B.modexp(&a, &p);

    // s = A^b mod p
    //   = B^a mod p
    //   = g^ab mod p
    //   = 1^ab mod p
    //   = 1

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
    m.input(&BigUint::one().to_bytes_le());
    m.result(&mut out);

    let msg_M = {
        let key_M = &out[0..16];
        decrypt(symm::Type::AES_128_CBC, key_M, &iv, &ctxt)
    };

    assert_eq!(&msg_B, &msg_M);
}

#[test]
fn run_g_p() {
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

    // g = p => s = 0
    let g = p.clone();

    // Alice
    
    let mut a_bytes = [0_u8; 256];
    rng.fill_bytes(&mut a_bytes);
    let a = BigUint::from_bytes_le(&a_bytes);
    let A = g.modexp(&a, &p);

    // Bob
    
    let mut b_bytes = [0_u8; 256];
    rng.fill_bytes(&mut b_bytes);
    let b = BigUint::from_bytes_le(&b_bytes);
    let B = g.modexp(&b, &p);

    // A->B : p, g, A
    let s_B = A.modexp(&b, &p);

    // B->A : p, g, B
    let s_A = B.modexp(&a, &p);

    // s = A^b mod p
    //   = B^a mod p
    //   = g^ab mod p
    //   = p^ab mod p
    //   = 0

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

#[test]
fn run_g_pm1() {
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

    // g = p => s = 0
    let g = &p - &BigUint::one();

    // Alice
    
    let mut a_bytes = [0_u8; 256];
    rng.fill_bytes(&mut a_bytes);
    let a = BigUint::from_bytes_le(&a_bytes);
    let A = g.modexp(&a, &p);

    // Bob
    
    let mut b_bytes = [0_u8; 256];
    rng.fill_bytes(&mut b_bytes);
    let b = BigUint::from_bytes_le(&b_bytes);
    let B = g.modexp(&b, &p);

    // A->B : p, g, A
    let s_B = A.modexp(&b, &p);

    // B->A : p, g, B
    let s_A = B.modexp(&a, &p);

    // (p-1)^0 mod p = 1
    // (p-1)^1 mod p = p-1
    // (p-1)^2 mod p = p^2 - 2p + 1 mod p
    //               = 0 - 0 + 1 mod p
    //               = 1
    // (p-1)^n mod p = (p-1)^2 * (p-1)^(n-2) mod p
    //               = 1 * (p-1)^(n-2) mod p
    //               = 1   if n % 2 == 0
    //                 p-1 otherwise

    // s = A^b mod p
    //   = B^a mod p
    //   = g^ab mod p
    //   = (p-1)^ab mod p
    //   = 1   if ab % 2 == 0
    //     p-1 otherwise

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
    m.input(&BigUint::one().to_bytes_le());
    m.result(&mut out);

    let msg_M_1 = {
        let key_M = &out[0..16];
        decrypt(symm::Type::AES_128_CBC, key_M, &iv, &ctxt)
    };

    // g = p - 1
    m.reset();
    m.input(&g.to_bytes_le());
    m.result(&mut out);

    let msg_M_2 = {
        let key_M = &out[0..16];
        decrypt(symm::Type::AES_128_CBC, key_M, &iv, &ctxt)
    };

    assert!(&msg_B == &msg_M_1 || &msg_B == &msg_M_2);
}
