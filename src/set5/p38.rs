use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

use num::{BigInt, FromPrimitive};
use num::bigint::Sign;
use rand::{Rng, weak_rng, XorShiftRng};
use rust_crypto::digest::Digest;
use rust_crypto::sha2::Sha256;
use rust_crypto::hmac::Hmac;
use rust_crypto::mac::{Mac, MacResult};

use math::ModExp;

fn gen_server(g: &BigInt, p: &BigInt) -> ([u8; 32], BigInt, BigInt, BigInt) {
    let mut salt = [0_u8; 32];
    let mut b_bytes = [0_u8; 32];
    let mut u_bytes = [0_u8; 32];

    let mut rng = weak_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut b_bytes);
    rng.fill_bytes(&mut u_bytes);

    let b = BigInt::from_bytes_le(Sign::Plus, &b_bytes);
    let u = BigInt::from_bytes_le(Sign::Plus, &u_bytes);
    let B = g.modexp(&b, p);

    (salt, b, B, u)
}

fn gen_client(g: &BigInt, p: &BigInt) -> (BigInt, BigInt) {
    let mut a_bytes = [0_u8; 32];
    let mut rng = weak_rng();
    rng.fill_bytes(&mut a_bytes);

    let a = BigInt::from_bytes_le(Sign::Plus, &a_bytes);
    let A = g.modexp(&a, p);

    (a, A)
}

fn gen_client_hmac(password: &[u8], salt: &[u8], p: &BigInt,
                   a: &BigInt, B: &BigInt, u: &BigInt) -> MacResult {
    let mut output = [0_u8; 32];
    let mut m = Sha256::new();
    m.input(salt);
    m.input(password);
    m.result(&mut output);

    let x = BigInt::from_bytes_le(Sign::Plus, &output);
    let e = a + u * &x;
    let S = B.modexp(&e, p);

    let mut K = [0_u8; 32];
    m.reset();
    m.input(&S.to_bytes_le().1);
    m.result(&mut K);

    m.reset();
    let mut hmac = Hmac::new(m, &K);
    hmac.input(salt);
    hmac.result()
}

#[test]
fn run() {
    let g = BigInt::from_u32(2).unwrap();
    let p_bytes =
        b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
          e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
          3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
          6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
          24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
          c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
          bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
          fffffffffffff";
    let p = BigInt::from_bytes_le(Sign::Plus, p_bytes);
    let password = b"aarhus";

    let (salt, b, B, u) = gen_server(&g, &p);

    let (A, client_hmac) = {
        let (a, A) = gen_client(&g, &p);
        (A, gen_client_hmac(password, &salt, &p, &a, &B, &u))
    };

    // MITM attacker knows (A, b, B, u, salt, HMAC(K, salt))
    // S = B^(a + u*x) = g^(a*b) * g^(b*u*x) = A^b * C^x (mod p), 
    //     where C = g^(b*u)
    // => we can precompute A^b and C so we only have to do 1
    //    multiplication and 1 modexp per password guess.

    let g_ab = A.modexp(&b, &p);
    let bu = &b * &u;
    let g_bu = g.modexp(&bu, &p);

    let mut output = [0_u8; 32];
    let mut m = Sha256::new();

    let mut cracked_password: Option<Vec<u8>> = None;

    let reader = BufReader::new(File::open("/usr/share/dict/cracklib-small").unwrap());
    for line in reader.lines() {
        let password_guess = match line {
            Ok(l) => l.into_bytes(),
            Err(e) => panic!(e),
        };
        m.reset();
        m.input(&salt);
        m.input(&password_guess);
        m.result(&mut output);
        let x = BigInt::from_bytes_le(Sign::Plus, &output);

        let S = (&g_ab * &g_bu.modexp(&x, &p)) % &p;

        m.reset();
        m.input(&S.to_bytes_le().1);
        m.result(&mut output);

        let mut hmac = Hmac::new(Sha256::new(), &output);
        hmac.input(&salt);
        
        if hmac.result() == client_hmac {
            cracked_password = Some(password_guess);
            break;
        }
    }

    assert_eq!(&cracked_password.unwrap(), password);
}
