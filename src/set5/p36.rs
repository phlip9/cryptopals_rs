use num::{BigInt, Zero, One, FromPrimitive};
use num::bigint::Sign;
use rand::{Rng, weak_rng};
use rust_crypto::digest::Digest;
use rust_crypto::sha2::Sha256;
use ssl::symm::{self, encrypt, decrypt};

use math::ModExp;

// Set 5.36: Implement Secure Remote Password (SRP)

#[test]
fn run() {
    // Client and Server
    //
    // agree on p = NIST prime, g = 2, k = 3, I = email, P = password

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
    let p = BigInt::from_bytes_le(Sign::Plus, p_bytes);

    let g = BigInt::from_u32(2).unwrap();
    let k = BigInt::from_u32(3).unwrap();

    // Server
    //
    // x = H(salt || password)  (hash of salted password projected into group)
    // v = g^x (mod p)          (password-public key mix term)
   
    let (v, salt) = {
        let P = b"password";
        let mut salt = [0_u8; 32];
        rng.fill_bytes(&mut salt);

        let mut m = Sha256::new();
        m.input(&salt);
        m.input(P);
        let mut xH = [0_u8; 32];
        m.result(&mut xH);
        let x = BigInt::from_bytes_le(Sign::Plus, &xH);

        (g.modexp(&x, &p), salt)
    };

    // Client
    //
    // a = client secret
    // A = g^a (mod p)          (client "public" value)
    
    let (A, a) = {
        let mut a_bytes = [0_u8; 256];
        rng.fill_bytes(&mut a_bytes);
        let a = BigInt::from_bytes_le(Sign::Plus, &a_bytes);
        let A = g.modexp(&a, &p);
        (A, a)
    };

    // Server
    //
    // b = server secret
    // B = (k*v + g^b) (mod p)  (server "public" value with password mixed in)
    
    let (B, b) = {
        let mut b_bytes = [0_u8; 256];
        rng.fill_bytes(&mut b_bytes);
        let b = BigInt::from_bytes_le(Sign::Plus, &b_bytes);
        let t = g.modexp(&b, &p);
        let B = (&v * &k + &t) % &p;
        (B, b)
    };

    // Client, Server
    //
    // u = H(A || B)            ("public" mixer term)
    
    let u = {
        let mut uH = [0_u8; 32];
        let mut m = Sha256::new();
        m.input(&A.to_bytes_le().1);
        m.input(&B.to_bytes_le().1);
        m.result(&mut uH);
        BigInt::from_bytes_le(Sign::Plus, &uH)
    };

    // Client
    //
    // S = (B - k*g^x)^(a + u*x) (mod p)    (client-server shared secret)
    //   = (k*v + g^b - k*g^x)^(a + u*x) (mod p)
    //   = (k*g^x - k*g^x + g^b)^(a + u*x) (mod p)
    //   = (g^b)^(a + u*x) (mod p)
    //   = g^(a*b + b*u*x) (mod p)
    //   = g^(a*b) * g^(b*u*x) (mod p)
    //   = (g^a * g^(u*x))^b (mod p)
    //   = (A * v^u)^b (mod p)
    // K = H(S)

    let K_C = {
        let mut xH = [0_u8; 32];
        let P = b"password";
        let mut m = Sha256::new();
        m.input(&salt);
        m.input(P);
        m.result(&mut xH);
        let x = BigInt::from_bytes_le(Sign::Plus, &xH);
        let y = g.modexp(&x, &p);
        let z = &B - &k * &y;
        let e = &a + &u * &x;
        let S = z.modexp(&e, &p);
        let mut K = [0_u8; 32];
        m.reset();
        m.input(&S.to_bytes_le().1);
        m.result(&mut K);
        K
    };

    // Server
    // 
    // S = (A * v^u)^b (mod p)              (client-server shared secret)
    // K = H(S)
    
    let K_S = {
        let S = (&A * &v.modexp(&u, &p)).modexp(&b, &p);
        let mut K = [0_u8; 32];
        let mut m = Sha256::new();
        m.input(&S.to_bytes_le().1);
        m.result(&mut K);
        K
    };

    // Client and Server shared secrets should be equal
    assert_eq!(K_C, K_S);
}
