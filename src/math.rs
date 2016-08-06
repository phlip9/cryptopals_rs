use num::{Integer, Zero, One, BigInt, BigUint, FromPrimitive, ToPrimitive};

pub trait ModExp: Integer {
    fn modexp(&self, exp: &Self, md: &Self) -> Self;
}

macro_rules! modexp_impl {
    ($($t:ty),*) => ($(
        impl ModExp for $t  {
            fn modexp(&self, exp: &Self, m: &Self) -> Self {
                if m == &Self::one() {
                    return Self::zero();
                }
                let mut r = Self::one();
                let mut b = self % m;
                let mut e = exp.clone();
                while !e.is_zero() {
                    if e.is_odd() {
                        r = (&r * &b) % m;
                    }
                    e = &e >> 1;
                    b = (&b * &b) % m;
                }
                r
            }
        }
    )*)
}

modexp_impl! { u8, u16, u32, u64, usize, i8, i16, i32, i64, isize, BigInt, BigUint }

#[test]
fn test_modexp() {
    assert_eq!(6_u32, 5_u32.modexp(&9, &37));
    
    let b = BigUint::from_u32(5).unwrap();
    let e = BigUint::from_u32(9).unwrap();
    let m = BigUint::from_u32(37).unwrap();
    let r = b.modexp(&e, &m).to_u32().unwrap();
    assert_eq!(6, r);
}
