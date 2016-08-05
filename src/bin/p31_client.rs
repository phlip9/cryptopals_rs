#![feature(inclusive_range_syntax)]

extern crate hyper;
extern crate rand;
extern crate rustc_serialize as serialize;

use std::f32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;
use std::thread;

use hyper::client::Client;
use hyper::status::StatusCode;
use rand::{Rng, weak_rng};
use serialize::hex::ToHex;

// Generate some full-rank byte permutation matrices in Python
//
// >>> import random
// >>> U = [i for i in range(256)]
// >>> def count_bits(x):
// ...   count = 0
// ...   for i in range(8):
// ...     count += (x & (1 << i)) >> i
// ...   return count
// ...
// >>> def dot(A, x):
// ...   y = 0
// ...   for i in range(8):
// ...     y |= (count_bits(A[7 - i] & x) & 1) << i
// ...   return y
// ...
// >>> for j in range(10):
// ...   A = random.sample(U, 8)
// ...   while len(set([dot(A, i) for i in range(256)])) != 256:
// ...     A = random.sample(U, 8)
// ...   print(', '.join("0x%02x" % a for a in A) + ',')
// ...
const N_MATS: usize = 10;
const N_ROWS: usize = 8 * N_MATS;
const PERM_MATS: [u8; N_ROWS] = [
    0x5d, 0x6b, 0x62, 0x95, 0xdd, 0x5e, 0xb9, 0xd3,
    0xce, 0x92, 0x68, 0x93, 0x33, 0x8a, 0x86, 0xcd,
    0x56, 0x0a, 0xc9, 0x4b, 0xee, 0x65, 0xbf, 0x2c,
    0x8e, 0x52, 0x5f, 0x4d, 0x64, 0x79, 0xa1, 0x55,
    0xca, 0x6f, 0x22, 0x61, 0x47, 0xa7, 0x79, 0xd7,
    0x49, 0x03, 0x66, 0x74, 0xbc, 0x7d, 0xcd, 0x61,
    0x17, 0x09, 0x81, 0xa0, 0x9e, 0x05, 0x99, 0x7b,
    0xe0, 0xce, 0x1f, 0x68, 0x7f, 0xc4, 0x2d, 0x1a,
    0xf1, 0xaf, 0xad, 0xd4, 0xf7, 0x70, 0x4c, 0x75,
    0x47, 0x12, 0xf2, 0x84, 0x89, 0x1a, 0x04, 0x3f,
];

// byte matrix-vector product
fn dot(A: &[u8], x: u8) -> u8 {
    let mut y = 0_u8;
    for i in 0..8 {
        y |= ((A[7 - i] & x).count_ones() as u8 & 1) << i;
    }
    y
}

fn argmax<T: PartialOrd>(xs: &[T]) -> Option<usize> {
    if xs.len() == 0 {
        None
    } else {
        let mut i = 0;
        let mut max = &xs[i];
        for j in 1..xs.len() {
            if &xs[j] > max {
                i = j;
                max = &xs[j];
            }
        }
        Some(i)
    }
}

struct Task {
    byte: u8,
    mac: [u8; 20],
}

struct TaskRet {
    byte: u8,
    ns_elapsed: u64,
}

fn challenge_mac(client: &Client, task: &Task) -> TaskRet {
    let mut ns_elapsed: u64 = 0;
    let file = "20.txt";
    let mac_str = task.mac.to_hex();
    let url = format!("http://localhost:5000/verify?file={}&signature={}", file, &mac_str);
    let now = Instant::now();
    client.get(&url)
        .send()
        .unwrap();
    let elapsed = now.elapsed();
    let secs = elapsed.as_secs() as u64;
    let nanos = elapsed.subsec_nanos() as u64;
    ns_elapsed += secs * 1_000_000_000_u64 + nanos;
    TaskRet {
        byte: task.byte,
        ns_elapsed: ns_elapsed,
    }
}

fn main() {
    let mut mac = [0_u8; 20];
    let mut timing_vec = [0_u64; 256];

    let done = Arc::new(AtomicBool::new(false));
    let task_queue = Arc::new(Mutex::new(Vec::new()));
    let (c_tx, p_rx) = mpsc::channel();

    let thread_handles = (0..3).map(|t| {
        let done = done.clone();
        let c_tx = c_tx.clone();
        let task_queue = task_queue.clone();

        thread::spawn(move || {
            let client = Client::new();

            loop {
                if done.load(Ordering::Relaxed) {
                    break;
                }
                let maybe_task = {
                    let mut tq = task_queue.lock().unwrap();
                    tq.pop()
                };
                match maybe_task {
                    Some(task) => {
                        let task_ret = challenge_mac(&client, &task);
                        c_tx.send(task_ret).unwrap();
                    },
                    None => continue
                }
            }
        })
    }).collect::<Vec<_>>();

    let mut rng = weak_rng();

    for i in 0..20 {
        let repeats = 150/(i+1) + 45;

        for k in 0..repeats {
            let j = rng.gen_range(0, N_MATS);
            let A = &PERM_MATS[8*j..8*(j+1)];
            
            for b in 0...255 {
                let b_p = dot(A, b);
                mac[i] = b_p;
                let task = Task {
                    byte: b_p,
                    mac: mac.clone(),
                };
                let mut tq = task_queue.lock().unwrap();
                tq.push(task);
            }
        }

        for l in 0..256 {
            timing_vec[l] = 0;
        }

        for _ in 0..256*repeats {
            let task_ret = p_rx.recv().unwrap();
            timing_vec[task_ret.byte as usize] += task_ret.ns_elapsed;
        }

        if p_rx.try_recv().is_ok() {
            panic!("too many items produced");
        }

        for m in 0..256 {
            let avg_ms = timing_vec[m] as f64 / (repeats as f64 * 1e6);
            println!("0x{:02x} => {} ms", m as u8, avg_ms);
        }

        let next_byte = argmax(&timing_vec).unwrap() as u8;

        println!("=== 0x{:02x} ===", next_byte);

        mac[i] = next_byte;
    }

    &done.store(true, Ordering::Relaxed);
    drop(p_rx);

    let file = "20.txt";
    let mac_str = mac.to_hex();
    let url = format!("http://localhost:5000/verify?file={}&signature={}", file, &mac_str);

    let client = Client::new();
    let res = client.get(&url)
        .send()
        .unwrap();

    println!("res = {:?}", &res);

    assert_eq!(res.status, StatusCode::Ok);
}
