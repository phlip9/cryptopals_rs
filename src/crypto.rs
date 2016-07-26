pub mod pkcs7 {
    pub fn pad(mut data: Vec<u8>, blocksize: usize) -> Vec<u8> {
        assert!(blocksize < 256);

        let len = data.len();
        let rem = len % blocksize;
        let pad = (blocksize - rem) as u8;

        for _ in 0..pad {
            data.push(pad);
        }

        data
    }

    pub fn unpad(mut data: Vec<u8>) -> Option<Vec<u8>> {
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
    fn test_pad() {
        let mut data = "AAAABBBBCC".to_string().into_bytes();
        data = pad(data, 4);
        assert_eq!("AAAABBBBCC\x02\x02", &String::from_utf8_lossy(&data));
        data = "AAAABBBB".to_string().into_bytes();
        data = pad(data, 4);
        assert_eq!("AAAABBBB\x04\x04\x04\x04", &String::from_utf8_lossy(&data));
    }

    #[test]
    fn test_unpad() {
        let mut a = "ABCD\x04\x04\x04\x04".as_bytes().to_vec();
        a = unpad(a).unwrap();
        assert_eq!(a, "ABCD".as_bytes());
        a = "ABCD\x01\x02\x03\x04".as_bytes().to_vec();
        let mut res = unpad(a);
        assert!(res.is_none());
        a = "ABCD\x04\x04".as_bytes().to_vec();
        res = unpad(a);
        assert!(res.is_none());
    }
}
