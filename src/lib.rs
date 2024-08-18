#![allow(dead_code)]

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

#[derive(Clone, Copy, Debug, PartialEq)]
struct Seed([u8; 16]);

impl Distribution<Seed> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Seed {
        Seed(rng.gen())
    }
}

impl Seed {
    fn expand(&self) -> ExpandedSeed {
        let key = GenericArray::from(self.0);
        let cipher = Aes128::new(&key);
        let mut blocks = [GenericArray::from([0; 16]), GenericArray::from([1; 16])];
        cipher.encrypt_blocks(&mut blocks);
        let [mut s0, mut s1] = blocks;
        let b0 = if s0[0] & 0x01 == 1 { true } else { false };
        let b1 = if s1[0] & 0x01 == 1 { true } else { false };
        s0[0] &= 0xFE;
        s1[0] &= 0xFE;
        ExpandedSeed {
            s: [Seed(s0.into()), Seed(s1.into())],
            b: [b0, b1],
        }
    }

    fn zero() -> Seed {
        Self([0; 16])
    }
}

impl std::ops::BitXor for Seed {
    type Output = Seed;
    fn bitxor(mut self, rhs: Self) -> Seed {
        self ^= rhs;
        self
    }
}

impl std::ops::BitXorAssign<Seed> for Seed {
    fn bitxor_assign(&mut self, other: Seed) {
        for i in 0..16 {
            self.0[i] ^= other.0[i];
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ExpandedSeed {
    s: [Seed; 2],
    b: [bool; 2],
}

impl ExpandedSeed {
    fn correct_with(&mut self, cw: &CorrectionWord) {
        self.s[0] ^= cw.s;
        self.b[0] ^= cw.b[0];
        self.s[1] ^= cw.s;
        self.b[1] ^= cw.b[1];
    }

    fn into_selected(self, alpha: bool) -> Seed {
        todo!();
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct CorrectionWord {
    s: Seed,
    b: [bool; 2],
}

fn gen(alpha: bool) -> (CorrectionWord, [Seed; 2]) {
    let mut rng = thread_rng();
    let s0 = rng.gen::<Seed>();
    let s1 = rng.gen::<Seed>();
    let e0 = s0.expand();
    let e1 = s1.expand();
    let a = alpha as usize;
    let cw = CorrectionWord {
        s: e0.s[a] ^ e1.s[a],
        b: [e0.b[a] ^ e1.b[a], !(e0.b[a] ^ e1.b[a])],
    };
    (cw, [s0, s1])
}

fn eval(cw: &CorrectionWord, s: &Seed, b: bool, alpha: bool) -> Seed {
    let mut e = s.expand();
    if b {
        e.correct_with(cw);
    }

    if alpha {
        e.s[0]
    } else {
        e.s[1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let alpha = thread_rng().gen();
        let (cw, [s0, s1]) = gen(alpha);

        // on path
        {
            let s0 = eval(&cw, &s0, false, alpha);
            let s1 = eval(&cw, &s1, true, alpha);
            assert_ne!(s0, s1);
        }

        // off path
        {
            let s0 = eval(&cw, &s0, false, !alpha);
            let s1 = eval(&cw, &s1, true, !alpha);
            assert_eq!(s0, s1);
        }
    }
}
