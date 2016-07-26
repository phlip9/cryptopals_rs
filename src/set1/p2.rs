use util::xor_bytes;
use serialize::hex::{FromHex, ToHex};

#[test]
fn run() {
    let src = "1c0111001f010100061a024b53535009181c";
    let xor = "686974207468652062756c6c277320657965";
    let out_exp = "746865206b696420646f6e277420706c6179";
    let src_buf = src.from_hex().unwrap();
    let xor_buf = xor.from_hex().unwrap();
    let out_bytes = xor_bytes(&src_buf, &xor_buf);
    let out_act = out_bytes.to_hex();
    assert_eq!(out_exp, out_act);
}
