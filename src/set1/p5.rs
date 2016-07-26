use serialize::hex::ToHex;

use util::xor_bytes;

#[test]
fn run() {
    let m = "Burning 'em, if you ain't quick and nimble\n\
             I go crazy when I hear a cymbal";
    let bytes = m.as_bytes();
    let key = "ICE";
    let xor = key.as_bytes();
    let cipher_bytes = xor_bytes(&bytes, &xor);
    let cipher_text = cipher_bytes.to_hex();
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a\
                    26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027\
                    630c692b20283165286326302e27282f";
    assert_eq!(expected, cipher_text);
}
