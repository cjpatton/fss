#![allow(dead_code)] // TODO Delete this line

use prio::{
    field::FieldElementWithInteger,
    vdaf::xof::{IntoFieldVec, XofFixedKeyAes128Key},
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
    fn extend(&self, fixed_key: &XofFixedKeyAes128Key) -> ExtendedSeed {
        let mut out = [0; 32];
        fixed_key.with_seed(&self.0).fill(&mut out[..]);
        let (s0, s1) = out.split_at_mut(16);
        let b0 = if s0[0] & 0x01 == 1 { true } else { false };
        let b1 = if s1[0] & 0x01 == 1 { true } else { false };
        s0[0] &= 0xFE;
        s1[0] &= 0xFE;
        ExtendedSeed {
            s: [Seed(s0.try_into().unwrap()), Seed(s1.try_into().unwrap())],
            b: [b0, b1],
        }
    }

    fn convert<F: FieldElementWithInteger>(&self, fixed_key: &XofFixedKeyAes128Key) -> F {
        // NOTE We tweak the seed so that the input blocks input to AES do not collide with the
        // input blocks for `extend()`. This is an ugly hack that makes an assumption about how the
        // XOF works. It probably shouldn't be copied.
        //
        // TODO Add a test that asserts the output of `extend()` doesn't overlap with `convert()`.
        let mut seed = self.0.clone();
        seed[15] ^= 1;
        fixed_key.with_seed(&seed).into_field_vec(1)[0]
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
    fixed_key: XofFixedKeyAes128Key,
}

impl Idpf {
    fn new(nonce: &[u8; 16]) -> Self {
        Self {
            fixed_key: XofFixedKeyAes128Key::new(b"coolguy", nonce),
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
            // Selection maintains the following invariant, after correction:
            //
            // * If evaluation is on path, then the seed and control bit should be a pseudorandom
            //   seed and `bit` respectively. The pseudorandom seed is the sum of the shares of the
            //   seeds we're "losing" from the extended seed.
            //
            // * If evaluation is off path, then the seed and control bit should be equal to
            //  `Seed::zero()` and `!bit` respectively.
            let mut e0 = s0.extend(&self.fixed_key);
            let mut e1 = s1.extend(&self.fixed_key);
            let keep = usize::from(bit);
            let lose = 1 - keep;
            let mut cw = CorrectionWord {
                s: e0.s[lose] ^ e1.s[lose],
                b: [!bit ^ e0.b[0] ^ e1.b[0], bit ^ e0.b[1] ^ e1.b[1]],
                w: F::zero(), // computed in the next step
            };

            // Correct and select the next seed and control bit.
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

            // Conversion works as follows:
            //
            // * If evaluation is on path, then we `b0` and `b1` will have different values. in
            //   which case one of the servers will add the correction `cw.w` into their share of
            //   the output. We want the shares to sum up to `beta`.
            //
            // * If evaluation is off path, then `b0` and `b1` will have the same value, in which
            //   case both servers will add the correction or neither will. In this case, we want
            //   their shares to sum up to `0`.
            //
            // In either case, both servers will add a share. To make the on-path case work, have
            // server 0 add `w0` and server 1 add `-w1` so that `cw.w + w0 - w1` adds up to `beta`.
            // In case we're off path and both servers add the correction word, we need one to add
            // the negation.
            cw.w = beta - s0.convert(&self.fixed_key) + s1.convert(&self.fixed_key);
            if b1 {
                cw.w = -cw.w;
            }
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
        for (cw, bit) in correction_words.iter().zip(alpha.iter().copied()) {
            // Select the next seed and control bit.
            let mut e = s.extend(&self.fixed_key);
            if b {
                e.correct_with(cw);
            }
            (s, b) = e.into_selected(bit);
        }

        // Conversion.
        let cw_w = correction_words[alpha.len() - 1].w;
        let w = if !id && !b {
            s.convert::<F>(&self.fixed_key)
        } else if !id && b {
            cw_w + s.convert::<F>(&self.fixed_key)
        } else if id && !b {
            -s.convert::<F>(&self.fixed_key)
        // id && b
        } else {
            -(cw_w + s.convert(&self.fixed_key))
        };

        (s, w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prio::field::Field64;

    #[test]
    fn on_path() {
        let mut rng = thread_rng();
        let idpf = Idpf::new(&rng.gen());

        let alpha = std::iter::repeat_with(|| rng.gen())
            .take(137)
            .collect::<Vec<_>>();
        let beta = Field64::from(1337);
        let (cw, [k0, k1]) = idpf.gen(&alpha, beta);

        for i in 1..alpha.len() + 1 {
            let (s0, w0) = idpf.eval(&cw, &k0, false, &alpha[..i]);
            let (s1, w1) = idpf.eval(&cw, &k1, true, &alpha[..i]);
            assert_ne!(s0, s1);
            assert_eq!(beta, w0 + w1);
        }
    }

    #[test]
    fn off_path() {
        let mut rng = thread_rng();
        let idpf = Idpf::new(&rng.gen());
        let alpha = std::iter::repeat_with(|| rng.gen())
            .take(137)
            .collect::<Vec<_>>();
        let beta = Field64::from(1337);
        let (cw, [k0, k1]) = idpf.gen(&alpha, beta);

        let path = alpha.iter().copied().map(|bit| !bit).collect::<Vec<_>>();
        for i in 1..path.len() + 1 {
            let (s0, w0) = idpf.eval(&cw, &k0, false, &path[..i]);
            let (s1, w1) = idpf.eval(&cw, &k1, true, &path[..i]);
            assert_eq!(s0, s1);
            assert_eq!(Field64::from(0), w0 + w1);
        }
    }

    #[test]
    fn partial_path() {
        let mut rng = thread_rng();
        let idpf = Idpf::new(&rng.gen());
        let alpha = std::iter::repeat_with(|| rng.gen())
            .take(5)
            .collect::<Vec<_>>();
        let beta = Field64::from(1337);
        let (cw, [k0, k1]) = idpf.gen(&alpha, beta);

        for j in 0..alpha.len() {
            // on path until a certain level `j`
            let mut path = alpha.clone();
            path[j] = !path[j];
            for i in 1..j + 1 {
                let (s0, w0) = idpf.eval(&cw, &k0, false, &path[..i]);
                let (s1, w1) = idpf.eval(&cw, &k1, true, &path[..i]);
                assert_ne!(s0, s1);
                assert_eq!(beta, w0 + w1);
            }

            for i in j + 1..path.len() + 1 {
                let (s0, w0) = idpf.eval(&cw, &k0, false, &path[..i]);
                let (s1, w1) = idpf.eval(&cw, &k1, true, &path[..i]);
                assert_eq!(s0, s1);
                assert_eq!(Field64::from(0), w0 + w1);
            }
        }
    }
}
