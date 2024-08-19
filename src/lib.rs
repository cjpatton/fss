#![allow(dead_code)]

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
use prio::field::Field64;
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
    fn extend(&self, cipher: &Aes128) -> ExtendedSeed {
        let mut blocks = [GenericArray::from(self.0), GenericArray::from(self.0)];
        blocks[0][0] ^= 0x01;
        blocks[1][0] ^= 0x02;
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

    fn convert(&self, cipher: &Aes128) -> Field64 {
        let mut block = GenericArray::from(self.0);
        block[0] ^= 0x03;
        cipher.encrypt_block(&mut block);
        Field64::from(u64::from_le_bytes(block[..8].try_into().unwrap()))
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

    fn into_selected(self, bit: bool) -> (Seed, bool) {
        (self.s[bit as usize], self.b[bit as usize])
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct CorrectionWord {
    s: Seed,
    b: [bool; 2],
    w: Field64,
}

struct Idpf {
    cipher: Aes128,
}

impl Idpf {
    fn new(fixed_key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(&GenericArray::from(*fixed_key)),
        }
    }

    fn gen(&self, alpha: &[bool], _beta: Field64) -> (Vec<CorrectionWord>, [Seed; 2]) {
        let mut rng = thread_rng();
        let k0 = rng.gen::<Seed>();
        let k1 = rng.gen::<Seed>();
        let mut s0 = k0;
        let mut s1 = k1;
        let mut correction_words = Vec::with_capacity(alpha.len());
        for bit in alpha.iter().copied() {
            let e0 = s0.extend(&self.cipher);
            let e1 = s1.extend(&self.cipher);
            let keep = usize::from(bit);
            let lose = 1 - keep;
            s0 = e0.s[keep];
            s1 = e1.s[keep];
            let cw = CorrectionWord {
                s: e0.s[lose] ^ e1.s[lose],
                b: [!bit ^ e0.b[0] ^ e1.b[0], bit ^ e0.b[1] ^ e1.b[1]],
                w: Field64::from(0),
            };
            correction_words.push(cw);
        }
        (correction_words, [k0, k1])
    }

    fn eval(
        &self,
        correction_words: &[CorrectionWord],
        k: &Seed,
        id: bool,
        alpha: &[bool],
    ) -> Seed {
        let mut s = *k;
        let mut b = id;
        for (cw, bit) in correction_words.iter().zip(alpha.iter().copied()) {
            let mut e = s.extend(&self.cipher);
            if b {
                e.correct_with(cw);
            }
            (s, b) = e.into_selected(bit);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // Normally this would be derived from a random nonce chosen by the client.
        let idpf = Idpf::new(&[
            0xDC, 0xD6, 0x6F, 0x54, 0xFD, 0xB4, 0xF4, 0xB8, 0x9A, 0xCE, 0xA6, 0xF9, 0xBB, 0xDB,
            0xAD, 0xC0,
        ]);

        let alpha = thread_rng().gen::<[bool; 32]>().to_vec();
        let beta = Field64::from(1337);
        let (cw, [k0, k1]) = idpf.gen(&alpha, beta);

        // on path
        {
            for i in 1..alpha.len() {
                let out0 = idpf.eval(&cw, &k0, false, &alpha[..i]);
                let out1 = idpf.eval(&cw, &k1, true, &alpha[..i]);
                assert_ne!(out0, out1);
            }
        }

        // off path
        {
            let off_path = alpha.into_iter().map(|bit| !bit).collect::<Vec<_>>();
            for i in 1..off_path.len() {
                let out0 = idpf.eval(&cw, &k0, false, &off_path[..i]);
                let out1 = idpf.eval(&cw, &k1, true, &off_path[..i]);
                assert_eq!(out0, out1);
            }
        }
    }
}
