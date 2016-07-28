use std::time::{SystemTime, UNIX_EPOCH};

use rand::{Rng, SeedableRng, weak_rng};

use util::MT19937Rng;

fn epoch_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap()
        .as_secs()
}

#[test]
fn run() {
    let mut w_rng = weak_rng();
    let mut mt_rng = MT19937Rng::new_unseeded();

    let mut t = epoch_time();

    //// Oracle

    let wait1: u64 = w_rng.gen_range(10, 1000);
    t += wait1;

    let seed: u32 = (t & 0xFFFFFFFF) as u32;
    mt_rng.reseed(seed);

    let wait2: u64 = w_rng.gen_range(10, 1000);
    t += wait2;

    let out = mt_rng.next_u32();

    // Attacker

    // We simply step backward from our current time until a freshly seeded
    // rng produces the same out value.
    
    let mut recovered_seed = None;

    for i in 0..2000 {
        let seed2: u32 = ((t - i) & 0xFFFFFFFF) as u32;
        mt_rng.reseed(seed2);
        let out2 = mt_rng.next_u32();
        if out == out2 {
            recovered_seed = Some(seed2);
        }
    }

    assert!(recovered_seed.is_some());
    assert_eq!(seed, recovered_seed.unwrap());
}
