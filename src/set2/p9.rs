use crypto::pkcs7;

#[test]
fn run() {
    let mut data = "YELLOW SUBMARINE".to_string().into_bytes();
    data = pkcs7::pad(data, 20);
    assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04", &String::from_utf8_lossy(&data));
}
