pub trait Gcd {
    fn gcd(self, other: Self) -> Self;
}

macro_rules! gcd_impl {
    ($($t:ty),*) => ($(
        impl Gcd for $t {
            fn gcd(self, other: Self) -> Self {
                if self > other {
                    other.gcd(self)
                } else {
                    let mut a = self;
                    let mut b = other;
                    while b != 0 {
                        let r = a % b;
                        a = b;
                        b = r;
                    }
                    a
                }
            }
        }
    )*)
}

gcd_impl! { u8, usize }

#[test]
fn test_gcd() {
    assert_eq!(0_u8, 0_u8.gcd(0_u8));
    assert_eq!(3_u8, 9_u8.gcd(12_u8));
    assert_eq!(1_usize, 13_usize.gcd(17_usize));
}
