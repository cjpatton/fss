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
    fn extend(&self) -> ExtendedSeed {
        let key = GenericArray::from(self.0);
        let cipher = Aes128::new(&key);
        let mut blocks = [GenericArray::from([0; 16]), GenericArray::from([1; 16])];
        cipher.encrypt_blocks(&mut blocks);
        let [mut s0, mut s1] = blocks;
        let b0 = if s0[0] & 0x01 == 1 { true } else { false };
        let b1 = if s1[0] & 0x01 == 1 { true } else { false };
        s0[0] &= 0xFE;
        s1[0] &= 0xFE;
        ExtendedSeed {
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
struct ExtendedSeed {
    s: [Seed; 2],
    b: [bool; 2],
}

impl ExtendedSeed {
    fn correct_with(&mut self, cw: &CorrectionWord) {
        self.s[0] ^= cw.s;
        self.b[0] ^= cw.b[0];
        self.s[1] ^= cw.s;
        self.b[1] ^= cw.b[1];
    }

    fn into_selected(self, a: usize) -> (Seed, bool) {
        (self.s[a], self.b[a])
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct CorrectionWord {
    s: Seed,
    b: [bool; 2],
}

fn gen(alpha: &[bool]) -> (Vec<CorrectionWord>, [Seed; 2]) {
    let mut rng = thread_rng();
    let k0 = rng.gen::<Seed>();
    let k1 = rng.gen::<Seed>();
    let mut s0 = k0;
    let mut s1 = k1;
    let mut b = true;
    let mut correction_words = Vec::with_capacity(alpha.len());
    for bit in alpha.iter().copied() {
        let e0 = s0.extend();
        let e1 = s1.extend();
        let keep = usize::from(bit);
        let lose = 1 - keep;
        s0 = e0.s[keep];
        s1 = e1.s[keep];
        let cw = CorrectionWord {
            s: e0.s[lose] ^ e1.s[lose],
            b: [e0.b[0] ^ e1.b[0], !b ^ e0.b[1] ^ e1.b[1]],
        };
        b = cw.b[1];
        correction_words.push(cw);
    }
    (correction_words, [k0, k1])
}

fn eval(correction_words: &[CorrectionWord], k: &Seed, id: bool, alpha: &[bool]) -> Vec<Seed> {
    let mut s = *k;
    let mut b = id;

    let mut seeds = Vec::with_capacity(alpha.len());
    for (cw, a) in correction_words
        .iter()
        .zip(alpha.iter().copied().map(usize::from))
    {
        let mut e = s.extend();
        if b {
            e.correct_with(cw);
        }
        (s, b) = e.into_selected(a);
        seeds.push(s);
    }

    seeds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let alpha = thread_rng().gen::<[bool; 10]>().to_vec();
        let (cw, [s0, s1]) = gen(&alpha);

        // on path
        {
            let s0 = eval(&cw, &s0, false, &alpha);
            let s1 = eval(&cw, &s1, true, &alpha);
            assert_ne!(s0, s1);
        }

        // off path
        {
            let off_path = alpha.into_iter().map(|bit| !bit).collect::<Vec<_>>();
            let s0 = eval(&cw, &s0, false, &off_path);
            let s1 = eval(&cw, &s1, true, &off_path);
            assert_eq!(s0, s1);
        }
    }
}
