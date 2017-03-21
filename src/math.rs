use num::{Integer, Zero, One, BigInt, BigUint, FromPrimitive, ToPrimitive};

pub trait ModInv: Integer {
    fn modinv(&self, m: &Self) -> Self;
}

macro_rules! modinv_impl {
    ($($t:ty),*) => ($(
        impl ModInv for $t  {
            fn modinv(&self, m: &Self) -> Self {
                let mut s = Self::zero();
                let mut s_p = Self::one();
                let mut t = Self::one();
                let mut t_p = Self::zero();
                let mut r = m.clone();
                let mut r_p = self.clone();

                while !r.is_zero() {
                    let q = r_p.div_floor(&r);
                    let r_t = &r_p - &q * &r;
                    r_p = r;
                    r = r_t;
                    let s_t = &s_p - &q * &s;
                    s_p = s;
                    s = s_t;
                    let t_t = &t_p - &q * &t;
                    t_p = t;
                    t = t_t;
                }

                if r_p != Self::one() {
                    panic!("no modular inverse");
                }

                if s_p < Self::zero() {
                    s_p + m
                } else {
                    s_p
                }
            }
        }
    )*)
}

modinv_impl! { i8, i16, i32, i64, isize, BigInt }

pub fn modinv<T: ModInv>(a: T, b: T) -> T {
    a.modinv(&b)
}

#[test]
fn test_modinv() {
    assert_eq!(15, modinv(5_i32, 37_i32));
    assert_eq!(11, modinv(7_i32, 19_i32));

    let a = BigInt::from_u32(5).unwrap();
    let m = BigInt::from_u32(37).unwrap();
    let r = modinv(a, m).to_u32().unwrap();
    assert_eq!(15, r);
}

pub trait ModExp: Integer {
    fn modexp(&self, exp: &Self, m: &Self) -> Self;
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
                println!("r: {}", r);
                if &r < &Self::zero() {
                    let a = r + m;
                    a
                } else {
                    r
                }
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

#[test]
fn test_modexp_negative_base() {
    assert_eq!(31_i32, (-5_i32).modexp(&9, &37));

    let b = -(BigInt::from_u32(5).unwrap());
    let e = BigInt::from_u32(9).unwrap();
    let m = BigInt::from_u32(37).unwrap();
    let r = b.modexp(&e, &m).to_i32().unwrap();
    assert_eq!(31, r);
}
