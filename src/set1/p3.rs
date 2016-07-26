use serialize::hex::FromHex;

use freq::{dict, dict_englishness, most_english};
use util::xor_bytes;

#[test]
fn run() {
    let cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let cipher_bytes = cipher.from_hex().unwrap();
    let en_dict = dict("/usr/share/dict/american-english").unwrap();

    let (k, e) = most_english(&cipher_bytes, |m| dict_englishness(m, &en_dict));
    let xor = vec![k];
    let m = xor_bytes(&cipher_bytes, &xor);
    let string = String::from_utf8_lossy(&m);
    println!("{} : '{}' => {}", e, k as char, string);
    assert_eq!(string, "Cooking MC's like a pound of bacon");
}
