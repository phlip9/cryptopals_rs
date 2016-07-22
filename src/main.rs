#![allow(dead_code)]

#![feature(inclusive_range_syntax)]
#![feature(slice_patterns)]
#![feature(step_by)]

extern crate rustc_serialize as serialize;
extern crate openssl as ssl;
extern crate rand;

mod set1;
mod set2;

fn main() {
    set2::set_2_12();
}
