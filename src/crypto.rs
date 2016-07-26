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

    pub fn unpad(mut data: Vec<u8>) -> Vec<u8> {
        let len = data.len();
        let pad = data[len - 1] as usize;
        data.truncate(len - pad);
        data
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
        let mut data = "AAAABBBB\x04\x04\x04\x04".to_string().into_bytes();
        data = unpad(data);
        assert_eq!("AAAABBBB", &String::from_utf8_lossy(&data));
        data = "AAAABBBBCCC\x01".to_string().into_bytes();
        data = unpad(data);
        assert_eq!("AAAABBBBCCC", &String::from_utf8_lossy(&data));
    }
}
