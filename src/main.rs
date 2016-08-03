#![feature(inclusive_range_syntax)]
#![feature(slice_patterns)]
#![feature(step_by)]

extern crate crypto as rust_crypto;
extern crate openssl as ssl;
extern crate rand;
extern crate rustc_serialize as serialize;

mod crypto;
mod freq;
mod math;
mod util;
mod vector;

mod set1;
mod set2;
mod set3;
mod set4;
