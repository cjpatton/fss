use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};

#[derive(Debug, PartialEq)]
struct Seed([u8; 16]);

fn extend(seed: &Seed) -> [(Seed, bool); 2] {
    let key = GenericArray::from(seed.0);
    let cipher = Aes128::new(&key);
    let mut blocks = [GenericArray::from([0; 16]), GenericArray::from([1; 16])];
    cipher.encrypt_blocks(&mut blocks);
    let [mut s0, mut s1] = blocks;
    let b0 = if s0[0] & 0x01 == 1 { true } else { false };
    let b1 = if s1[0] & 0x01 == 1 { true } else { false };
    s0[0] &= 0xFE;
    s1[0] &= 0xFE;
    [(Seed(s0.into()), b0), (Seed(s1.into()), b1)]
}

impl std::ops::BitXor for Seed {
    type Output = Seed;

    fn bitxor(self, other: Self) -> Seed {
        let mut s = [0; 16];
        for i in 0..16 {
            s[i] = self.0[i] ^ other.0[i];
        }
        Seed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(Seed([0; 16]), Seed([23; 16]) ^ Seed([23; 16]));
    }
}
