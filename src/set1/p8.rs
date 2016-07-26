use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

use std::collections::HashSet;

use serialize::hex::FromHex;

fn repeated_blocks(data: &[u8], blocksize: usize) -> u32 {
    let mut count = 0;
    let mut set: HashSet<&[u8]> = HashSet::new();
    for chunk in data.chunks(blocksize) {
        if set.contains(chunk) {
            count += 1;
        } else {
            set.insert(chunk);
        }
    }
    count
}

#[test]
fn run() {
    let f = File::open("./data/8.txt").unwrap();
    let reader = BufReader::new(f);
    let blocksize: usize = 16;

    let line = reader.lines()
        .map(|line| line.unwrap())
        .max_by_key(|line| {
            let bytes = line.from_hex().unwrap();
            let n = repeated_blocks(&bytes, blocksize);
            if n != 0 {
                println!("{} | {}...", n, &line[0..15]);
            }
            n
        })
        .unwrap();

    println!("probable AES 128 ECB cipher text: {}...", &line[0..15]);
    assert_eq!("d880619740a8a19", &line[0..15]);
}
