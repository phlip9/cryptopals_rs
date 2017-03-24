use std::collections::HashMap;

use num::{BigInt, FromPrimitive};
use num::bigint::Sign;
use rand::{Rng, weak_rng, XorShiftRng};
use rust_crypto::digest::Digest;
use rust_crypto::sha2::Sha256;
use rust_crypto::hmac::Hmac;
use rust_crypto::mac::{Mac, MacResult};
use ssl::symm::{self, encrypt, decrypt};

use math::ModExp;

// Set 5.36: Implement Secure Remote Password (SRP)

struct Account {
    email: Vec<u8>,
    salt: [u8; 32],
    v: BigInt,
    login_state: Option<LoginState>,
}

struct LoginState {
    client_pubkey: BigInt,
    server_seckey: BigInt,
    server_pubkey: BigInt,
}

pub struct SRPServer {
    accounts: HashMap<Vec<u8>, Account>,
    g: BigInt,
    k: BigInt,
    p: BigInt,
    rng: XorShiftRng,
}

impl SRPServer {
    pub fn new(g: &BigInt, k: &BigInt, p: &BigInt) -> SRPServer {
        SRPServer {
            accounts: HashMap::new(),
            g: g.clone(),
            k: k.clone(),
            p: p.clone(),
            rng: weak_rng(),
        }
    }

    pub fn create_account(&mut self, email: &[u8], password: &[u8]) {
        let mut salt = [0_u8; 32];
        self.rng.fill_bytes(&mut salt);

        let x = gen_x(&salt, password);
        let v = self.g.modexp(&x, &self.p);

        let account = Account {
            email: email.to_vec(),
            salt: salt,
            v: v,
            login_state: None,
        };

        self.accounts.insert(email.to_vec(), account);
    }

    fn gen_server_keypair(&mut self, v: &BigInt) -> (BigInt, BigInt) {
        let mut b_bytes = [0_u8; 256];
        self.rng.fill_bytes(&mut b_bytes);

        let b = BigInt::from_bytes_le(Sign::Plus, &b_bytes);
        let t = self.g.modexp(&b, &self.p);
        let B = (v * &self.k + &t) % &self.p;

        (B, b)
    }

    fn gen_server_shared_secret(&self, acct: &Account) -> [u8; 32] {
        let v = &acct.v;
        let ls = &acct.login_state.as_ref().unwrap();

        let A = &ls.client_pubkey;
        let b = &ls.server_seckey;
        let B = &ls.server_pubkey;

        let u = gen_u(A, B);
        let S = (A * v.modexp(&u, &self.p)).modexp(b, &self.p);

        let mut K = [0_u8; 32];
        let mut m = Sha256::new();
        m.input(&S.to_bytes_le().1);
        m.result(&mut K);

        K
    }

    pub fn send_pubkey_dh(&mut self, email: &[u8], A: &BigInt) -> ([u8; 32], BigInt) {
        let v = self.accounts.get_mut(email).unwrap().v.clone();
        let (B, b) = self.gen_server_keypair(&v);

        let mut acct = self.accounts.get_mut(email).unwrap();
        acct.login_state = Some(LoginState {
            client_pubkey: A.clone(),
            server_seckey: b,
            server_pubkey: B.clone(),
        });

        (acct.salt.clone(), B)
    }

    pub fn validate_client_login(&self, email: &[u8], client_hmac: &MacResult) -> bool {
        let acct = self.accounts.get(email).unwrap();
        let K = self.gen_server_shared_secret(&acct);

        let mut hmac = Hmac::new(Sha256::new(), &K);
        hmac.input(&acct.salt);
        let server_hmac = hmac.result();

        let valid = &server_hmac == client_hmac;
        valid
    }
}

pub fn gen_client_keypair(rng: &mut Rng, g: &BigInt, p: &BigInt) -> (BigInt, BigInt) {
    let mut a_bytes = [0_u8; 256];
    rng.fill_bytes(&mut a_bytes);
    let a = BigInt::from_bytes_le(Sign::Plus, &a_bytes);
    let A = g.modexp(&a, &p);
    (A, a)
}

pub fn gen_u(A: &BigInt, B: &BigInt) -> BigInt {
    let mut uH = [0_u8; 32];
    let mut m = Sha256::new();
    m.input(&A.to_bytes_le().1);
    m.input(&B.to_bytes_le().1);
    m.result(&mut uH);
    let u = BigInt::from_bytes_le(Sign::Plus, &uH);
    u
}

pub fn gen_x(salt: &[u8], password: &[u8]) -> BigInt {
    let mut xH = [0_u8; 32];
    let mut m = Sha256::new();
    m.input(salt);
    m.input(password);
    m.result(&mut xH);
    let x = BigInt::from_bytes_le(Sign::Plus, &xH);
    x
}

#[test]
fn run() {
    let mut rng = weak_rng();
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

    let mut server = SRPServer::new(&g, &k, &p);

    let email = b"minsc@baldurs.gate";
    let password = b"spacehamster";

    server.create_account(email, password);
    let (A, a) = gen_client_keypair(&mut rng, &g, &p);
    let (salt, B) = server.send_pubkey_dh(email, &A);

    let u = gen_u(&A, &B);
    let x = gen_x(&salt, password);

    let y = g.modexp(&x, &p);
    let z = &B - &k * &y;
    let e = &a + &u * &x;
    let S = z.modexp(&e, &p);

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
