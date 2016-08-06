use rand::{Rng, weak_rng};
use num::{BigUint, FromPrimitive};

use math::ModExp;

use rust_crypto::digest::Digest;
use sha1::Sha1;

#[test]
fn run() {
    let g = BigUint::from_u32(2).unwrap();
    let p_bytes =
    b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
      e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
      3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
      6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
      24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
      c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
      bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
      fffffffffffff";

    let p = BigUint::parse_bytes(p_bytes, 16).unwrap();

    let mut rng = weak_rng();
    let mut a_bytes = [0_u8; 256];
    rng.fill_bytes(&mut a_bytes);
    let a = BigUint::from_bytes_le(&a_bytes);
    let A = g.modexp(&a, &p);

    let mut b_bytes = [0_u8; 256];
    rng.fill_bytes(&mut b_bytes);
    let b = BigUint::from_bytes_le(&b_bytes);
    let B = g.modexp(&b, &p);

    let s_1 = A.modexp(&b, &p);
    let s_2 = B.modexp(&a, &p);

    assert_eq!(s_1, s_2);
}
