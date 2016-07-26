use serialize::base64::{self, ToBase64};
use serialize::hex::FromHex;

#[test]
fn run() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f697 \
              36f6e6f7573206d757368726f6f6d";
    let b64_exp = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let b64_act = hex.from_hex().unwrap().to_base64(base64::STANDARD);
    assert_eq!(b64_exp, b64_act);
}
