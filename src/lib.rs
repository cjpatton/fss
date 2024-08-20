#![allow(dead_code)]

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
use prio::field::FieldElementWithInteger;
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

    fn convert<F: FieldElementWithInteger>(&self, cipher: &Aes128) -> F {
        let mut block = GenericArray::from(self.0);
        block[0] ^= 0x03;
        cipher.encrypt_block(&mut block);
        F::from(
            F::Integer::try_from(u64::from_le_bytes(block[..8].try_into().unwrap()) as usize)
                .unwrap(),
        )
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
    fn correct_with<F>(&mut self, cw: &CorrectionWord<F>) {
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
struct CorrectionWord<F> {
    s: Seed,
    b: [bool; 2],
    w: F,
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

    fn gen<F: FieldElementWithInteger>(
        &self,
        alpha: &[bool],
        beta: F,
    ) -> (Vec<CorrectionWord<F>>, [Seed; 2]) {
        let mut rng = thread_rng();
        let k0 = rng.gen::<Seed>();
        let k1 = rng.gen::<Seed>();
        let mut s0 = k0;
        let mut s1 = k1;
        let mut b0 = false;
        let mut b1 = true;
        let mut correction_words = Vec::with_capacity(alpha.len());
        for bit in alpha.iter().copied() {
            let mut e0 = s0.extend(&self.cipher);
            let mut e1 = s1.extend(&self.cipher);
            let keep = usize::from(bit);
            let lose = 1 - keep;
            let mut cw = CorrectionWord {
                s: e0.s[lose] ^ e1.s[lose],
                b: [!bit ^ e0.b[0] ^ e1.b[0], bit ^ e0.b[1] ^ e1.b[1]],
                w: F::zero(),
            };

            if b0 {
                e0.correct_with(&cw);
            }
            if b1 {
                e1.correct_with(&cw);
            }
            s0 = e0.s[keep];
            s1 = e1.s[keep];
            b0 = e0.b[keep];
            b1 = e1.b[keep];
            println!(
                "-{}\n-{}",
                s0.convert::<F>(&self.cipher),
                s1.convert::<F>(&self.cipher)
            );

            cw.w = beta - s0.convert(&self.cipher) - s1.convert(&self.cipher);
            correction_words.push(cw);
        }
        (correction_words, [k0, k1])
    }

    fn eval<F: FieldElementWithInteger>(
        &self,
        correction_words: &[CorrectionWord<F>],
        k: &Seed,
        id: bool,
        alpha: &[bool],
    ) -> (Seed, F) {
        let mut s = *k;
        let mut b = id;
        let mut w = F::zero();
        for (cw, bit) in correction_words.iter().zip(alpha.iter().copied()) {
            let mut e = s.extend(&self.cipher);
            w = F::zero();
            if b {
                e.correct_with(cw);
                w += cw.w;
            }
            (s, b) = e.into_selected(bit);
            w += s.convert(&self.cipher);
        }
        println!(" {w}");
        (s, w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prio::field::Field64;

    #[test]
    fn it_works() {
        // Normally this would be derived from a random nonce chosen by the client.
        let idpf = Idpf::new(&[
            0xDC, 0xD6, 0x6F, 0x54, 0xFD, 0xB4, 0xF4, 0xB8, 0x9A, 0xCE, 0xA6, 0xF9, 0xBB, 0xDB,
            0xAD, 0xC0,
        ]);

        let alpha = thread_rng().gen::<[bool; 10]>().to_vec();
        let beta = Field64::from(1337);
        let (cw, [k0, k1]) = idpf.gen(&alpha, beta);

        println!(" -- ");

        // on path
        {
            for i in 1..alpha.len() + 1 {
                let (s0, w0) = idpf.eval(&cw, &k0, false, &alpha[..i]);
                let (s1, w1) = idpf.eval(&cw, &k1, true, &alpha[..i]);
                assert_ne!(s0, s1);
                assert_eq!(beta, w0 + w1);
            }
        }

        println!(" -- ");

        // off path
        {
            let off_path = alpha.into_iter().map(|bit| !bit).collect::<Vec<_>>();
            for i in 1..off_path.len() + 1 {
                let (s0, w0) = idpf.eval(&cw, &k0, false, &off_path[..i]);
                let (s1, w1) = idpf.eval(&cw, &k1, true, &off_path[..i]);
                assert_eq!(s0, s1);
                assert_eq!(Field64::from(0), w0 + w1);
            }
        }
    }
}
