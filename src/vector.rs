pub type Vecf = Vec<f32>;

pub trait Normalize {
    fn norm(&self) -> Self;
}

impl Normalize for Vecf {
    fn norm(&self) -> Self {
        let len = self.len();
        let mut normed = Vecf::with_capacity(len);
        let mag_inv = 1.0 / self.mag();
        for i in 0..len {
            normed.push(mag_inv * self[i]);
        }
        normed
    }
}

pub trait Dot {
    type Output;
    fn dot(&self, other: &Self) -> Option<Self::Output>;
}

impl Dot for Vecf {
    type Output = f32;
    fn dot(&self, other: &Vecf) -> Option<f32> {
        let llen = self.len();
        let rlen = other.len();
        if llen != rlen {
            None
        } else {
            let mut sum = 0.0f32;
            for i in 0..llen {
                sum += self[i] * other[i];
            }
            Some(sum)
        }
    }
}

pub trait Magnitude {
    type Output;
    fn mag(&self) -> Self::Output;
}

impl Magnitude for Vecf {
    type Output = f32;
    fn mag(&self) -> f32 {
        self.dot(self).unwrap().sqrt()
    }
}

fn min<T: Ord>(a: T, b: T) -> T {
    if a > b { b } else { a }
}

fn max<T: Ord>(a: T, b: T) -> T {
    if a > b { a } else { b }
}

macro_rules! assert_approx_eq {
    ($a:expr, $b:expr) => ({
        let (a, b) = (&$a, &$b);
        assert!((*a - *b).abs() < 1.0e-6,
            "{} !=~ {}", *a, *b);
    })
}

fn assert_vec_approx_eq(v1: &Vecf, v2: &Vecf) {
    assert_eq!(v1.len(), v2.len());
    for i in 0..v1.len() {
        if (v1[i] - v2[i]).abs() >= 1.0e-6 {
            let l = max(i as i32 - 5, 0) as usize;
            let r = min(i + 5 + 1, v1.len());
            let v1_slice = &v1[l..r];
            let v2_slice = &v2[l..r];
            println!("");
            println!("    ... {:?} ...", v1_slice);
            println!("!=~ ... {:?} ...", v2_slice);
            assert_approx_eq!(v1[i], v2[i]);
            break;
        }
    }
}

#[test]
fn test_dot() {
    let v1: Vecf = vec![1.0f32, 1.0, 0.0, 0.0];
    let v2: Vecf = vec![1.0f32, 0.0, 1.0, 0.0];
    assert_approx_eq!(v1.dot(&v2).unwrap(), 1.0f32);

    let v3: Vecf = vec![1.0f32, 2.0, 4.0, 8.0];
    let v4: Vecf = vec![-1.0f32, 2.0, -4.0, 8.0];
    assert_eq!(v3.dot(&v4).unwrap(), 51.0f32);

    let v5: Vecf = vec![1.0f32, 1.0f32];
    assert!(v1.dot(&v5).is_none());
}

#[test]
fn test_mag() {
    let v1: Vecf = vec![0.0f32, 1.0, 0.0, 0.0];
    assert_approx_eq!(v1.mag(), 1.0f32);

    let v2: Vecf = vec![1.0f32, 1.0, 1.0, 1.0];
    assert_approx_eq!(v2.mag(), 2.0f32);
}

#[test]
fn test_norm() {
    let v1: Vecf = vec![0.0f32, 0.0, 1.0, 0.0];
    assert_vec_approx_eq(&v1.norm(), &v1);

    let v2: Vecf = vec![1.0f32, 0.0, -1.0, 0.0];
    let v2_n: Vecf = vec![0.70710677_f32, 0.0, -0.70710677_f32, 0.0];
    assert_vec_approx_eq(&v2.norm(), &v2_n);
}
