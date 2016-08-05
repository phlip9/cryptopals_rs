extern crate crypto as rust_crypto;
extern crate cryptopals_rs;
extern crate iron;
extern crate logger;
extern crate rand;
extern crate rustc_serialize as serialize;

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::thread;

use iron::prelude::*;
use iron::{BeforeMiddleware, typemap, status};
use logger::Logger;
use rand::{Rng, weak_rng};
use rust_crypto::digest::Digest;
use serialize::hex::{FromHex, ToHex};

use cryptopals_rs::sha1::Sha1;

const SLEEP_NS: u32 = 500_000_u32; // 0.5 ms
const FILE_BYTES: &'static [u8] = include_bytes!("../../data/20.txt");

fn insecure_compare<T: Eq>(a: &[T], b: &[T]) -> bool {
    for (a_i, b_i) in a.iter().zip(b) {
        if a_i != b_i {
            return false;
        } else {
            thread::sleep(Duration::new(0, SLEEP_NS));
        }
    }
    true
}

fn verify(key: &Key, file: &str, signature: &str) -> io::Result<bool> {
    //let mut path = PathBuf::from("/home/phlip9/dev/cryptopals_rs/data");
    //path.push(file);
    //let mut f = try!(File::open(path));
    //let mut buffer = [0_u8; 1024];
    let mut m = Sha1::new();
    m.input(&key.key);
    //loop {
        //let n = try!(f.read(&mut buffer));
        //m.input(&buffer[0..n]);
        //if n != 1024 {
            //break;
        //}
    //}
    m.input(FILE_BYTES);
    let mut mac = [0_u8; 20];
    m.result(&mut mac);
    println!("mac:           {}", mac.to_hex());
    println!("challenge_mac: {}", signature);
    let challenge_mac = signature.from_hex().unwrap();
    Ok(insecure_compare(&mac, &challenge_mac))
}

fn handle(req: &mut Request) -> IronResult<Response> {
    let key = req.extensions.get::<Key>().unwrap();

    let res: Option<Response> = Some(&req.url)
        .and_then(|url| {
            let path = &url.path();
            if path.len() == 1 || path[0] == "verify" {
                url.query()
            } else {
                None
            }
        })
        .and_then(|qs: &str| {
            let hmap = qs.split('&')
                .map(|pair| pair.split('=').collect::<Vec<_>>())
                .fold(HashMap::new(), |mut hmap, pair| {
                    if pair.len() == 2 {
                        let k = pair[0].to_string();
                        let v = pair[1].to_string();
                        hmap.insert(k, v);
                    }
                    hmap
                });
            match (hmap.get("file"), hmap.get("signature")) {
                (Some(file), Some(signature)) => Some(verify(&key, file, signature).unwrap()),
                _ => None
            }
        })
        .and_then(|valid| {
            match valid {
                true => Some(Response::with(status::Ok)),
                false => Some(Response::with(status::InternalServerError))
            }
        });

    match res {
        Some(val) => Ok(val),
        _ => Ok(Response::with(status::NotFound))
    }
}

#[derive(Copy, Clone)]
struct Key {
    key: [u8; 16]
}

impl typemap::Key for Key { type Value = Arc<Key>; }

struct KeyMiddleware {
    key: Arc<Key>
}

impl KeyMiddleware {
    fn new(key: Arc<Key>) -> KeyMiddleware {
        KeyMiddleware {
            key: key
        }
    }
}

impl BeforeMiddleware for KeyMiddleware {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        req.extensions.insert::<Key>(self.key.clone());
        Ok(())
    }
}

fn main() {
    let mut rng = weak_rng();
    let key = Arc::new(Key { key: rng.gen() });
    let key_middleware = KeyMiddleware::new(key);

    //let (logger_before, logger_after) = Logger::new(None);

    let mut chain = Chain::new(handle);
    //chain.link_before(logger_before);
    chain.link_before(key_middleware);
    //chain.link_after(logger_after);

    let host = "localhost:5000";
    println!("Starting new server at {}", host);

    Iron::new(chain).http(host).unwrap();
}
