// unpad pkcs7 padding with validation
fn unpad_pkcs7(mut data: Vec<u8>) -> Option<Vec<u8>> {
    let len = data.len();
    let pad = data[len - 1] as usize;
    if pad > len {
        return None;
    }
    for i in 0..pad {
        let idx = len - i - 1;
        if data[idx] != pad as u8 {
            return None;
        }
    }
    data.truncate(len - pad);
    Some(data)
}

#[test]
fn run() {
    let mut a = "ABCD\x04\x04\x04\x04".as_bytes().to_vec();
    a = unpad_pkcs7(a).unwrap();
    assert_eq!(a, "ABCD".as_bytes());
    a = "ABCD\x01\x02\x03\x04".as_bytes().to_vec();
    let mut res = unpad_pkcs7(a);
    assert!(res.is_none());
    a = "ABCD\x04\x04".as_bytes().to_vec();
    res = unpad_pkcs7(a);
    assert!(res.is_none());
}

