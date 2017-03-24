use num::{BigInt, Zero, FromPrimitive};
use num::bigint::Sign;
use rust_crypto::digest::Digest;
use rust_crypto::sha2::Sha256;
use rust_crypto::hmac::Hmac;
use rust_crypto::mac::{Mac, MacResult};

use set5::p36::SRPServer;

// To authenticate with an SRP server without valid credentials, we can just
// send A s.t. A is a multiple of the protocol prime, which means the 
// client/server shared secret is just 0.

fn create_server(email: &[u8], g: &BigInt, k: &BigInt, p: &BigInt) -> SRPServer {
    let mut server = SRPServer::new(&g, &k, &p);
    server.create_account(email, b"spacehamster");
    server
}

#[test]
fn run() {
    let g = BigInt::from_u32(2).unwrap();
    let k = BigInt::from_u32(3).unwrap();
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

    let email = b"minsc@baldurs.gate";
    let mut server = create_server(email, &g, &k, &p);

    let two = BigInt::from_i32(2).unwrap();
    let A_s = vec![BigInt::zero(), p.clone(), &p*&two];

    for A in &A_s {
        let (salt, _) = server.send_pubkey_dh(email, A);

        // A = 0, p, 2*p, ...
        // => A = 0 (mod p)
        // => S = (A * v^u)^b = (0 * v^u)^b = 0 (mod p)

        let S = BigInt::zero();

        let mut K = [0_u8; 32];
        let mut m = Sha256::new();
        m.reset();
        m.input(&S.to_bytes_le().1);
        m.result(&mut K);

        let mut hmac = Hmac::new(Sha256::new(), &K);
        hmac.input(&salt);
        let client_hmac = hmac.result();

        let valid_login = server.validate_client_login(email, &client_hmac);
        assert!(valid_login);
    }
}
