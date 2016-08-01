use rand::{weak_rng, Rng, SeedableRng};

use util::{MT19937Rng, prng_crypt};

#[test]
fn run() {
    let mut wk_rng = weak_rng();
    // rng seeded from weak 16-bit seed
    let seed = wk_rng.next_u32() & 0xFFFF;
    let mut ks_rng = MT19937Rng::from_seed(seed);

    let attack_input = "AAAAAAAAAAAAAA".as_bytes();
    let rand_prefix: [u8; 2] = wk_rng.gen();

    let mut input = Vec::new();
    input.extend_from_slice(&rand_prefix);
    input.extend_from_slice(attack_input);

    let ctxt = prng_crypt(&mut ks_rng, &input);

    let test_input = "__AAAAAAAAAAAAAA".as_bytes();

    // brute force seeds
    let rec_seed = (0..(1 << 16))
        .find(|&s: &u32| {
            ks_rng.reseed(s);
            let test_ctxt = prng_crypt(&mut ks_rng, &test_input);
            &ctxt[2..] == &test_ctxt[2..]
        });

    assert!(rec_seed.is_some());
    assert_eq!(seed, rec_seed.unwrap());
}
