use std::collections::BTreeMap;

use rand::{Rng, weak_rng};
use serialize::json::{Json, ToJson};
use ssl::symm::{self, encrypt, decrypt};

fn parse_querystr(input: &str) -> Result<Json, ()> {
    let mut obj = BTreeMap::new();
    for pair in input.split('&') {
        let mut items = pair.split('=');
        match (items.next(), items.next(), items.next()) {
            (Some(key), Some(val), None) => {
                obj.insert(key.to_string(), Json::String(val.to_string()));
            },
            _ => {
                return Err(());
            }
        };
    }
    Ok(Json::Object(obj))
}

#[test]
fn test_parse_queryst() {
    let json = parse_querystr("foo=bar&baz=wanker@foobar.com").unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(obj["foo"], "bar".to_json());
    assert_eq!(obj["baz"], "wanker@foobar.com".to_json());
}

fn profile_for(email: &str) -> String {
    let email_clean = email.replace(|c| c == '=' || c == '&', "");
    format!("email={}&uid={}&role=user", email_clean, 10)
}

fn encryption_oracle(key: &[u8], input: &str) -> Vec<u8> {
    let plaintext = profile_for(input);
    let data = plaintext.as_bytes();
    encrypt(symm::Cipher::aes_128_ecb(), key, None, data).unwrap()
}

fn decryption_oracle(key: &[u8], data: &[u8]) -> Json {
    let plaintext = decrypt(symm::Cipher::aes_128_ecb(), key, None, data).unwrap();
    let string = String::from_utf8_lossy(&plaintext);
    parse_querystr(&string).unwrap()
}

#[test]
fn run() {
    let blocksize = 16;
    let mut rng = weak_rng();
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);

    // 0123456789012345|0123456789012345|0123456789012345|012345678912345
    // email=AAAAAAAAAA|adminPPPPPPPPPPP|AAA&uid=10&role=|userPPPPPPPPPPP
    //       ^^^^^^^^^^|^^^^^^^^^^^^^^^^|^^^
    //                     input

    let input = "AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0bAAA";
    let mut ciphertext = encryption_oracle(&key, input);

    // substitute the block with admin text in it to make an admin profile!
    let admin_block = &ciphertext[1*blocksize..2*blocksize].to_vec();
    &mut ciphertext[3*blocksize..4*blocksize].copy_from_slice(&admin_block);

    let json = decryption_oracle(&key, &ciphertext);
    let obj = json.as_object().unwrap();
    assert_eq!(obj["role"], "admin".to_json());
}
