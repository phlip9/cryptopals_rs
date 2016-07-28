use rand::{Rng, SeedableRng};

use util::MT19937Rng;

#[test]
fn run() {
    let seed = 0x0_u32;
    let mut rng = MT19937Rng::from_seed(seed);
    
    println!("");
    for i in 0..630 {
        if i < 5 || i > 624 {
            println!("0x{:08x}", rng.next_u32());
        }
    }
}
