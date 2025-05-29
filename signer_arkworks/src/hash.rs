//! pasted from <https://github.com/noir-lang/noir/commit/e8bbce71fde3fc7af410c30920c2a547389d8248#diff-f6c7279401d09b1f7a59f5dd4a342a2c8a4770945e7a6e327d6d8d16fd995bb7>
//! until `bn254_blackbox_solver` is updated

use acvm_blackbox_solver::BlackBoxResolutionError;
use ark_bn254::Fr;

/// Performs a poseidon hash with a sponge construction equivalent to the one in poseidon2.nr
pub fn poseidon_hash(inputs: &[Fr]) -> Result<Fr, BlackBoxResolutionError> {
    let two_pow_64 = 18446744073709551616_u128.into();
    let iv = Fr::from(inputs.len()) * two_pow_64;
    let mut sponge = Poseidon2Sponge::new(iv, 3);
    for input in inputs.iter() {
        sponge.absorb(*input)?;
    }
    sponge.squeeze()
}

pub struct Poseidon2Sponge<'a> {
    rate: usize,
    poseidon: Poseidon2<'a>,
    squeezed: bool,
    cache: Vec<Fr>,
    state: Vec<Fr>,
}

impl<'a> Poseidon2Sponge<'a> {
    pub fn new(iv: Fr, rate: usize) -> Poseidon2Sponge<'a> {
        let mut result = Poseidon2Sponge {
            cache: Vec::with_capacity(rate),
            state: vec![Fr::zero(); rate + 1],
            squeezed: false,
            rate,
            poseidon: Poseidon2::new(),
        };
        result.state[rate] = iv;
        result
    }

    fn perform_duplex(&mut self) -> Result<(), BlackBoxResolutionError> {
        // zero-pad the cache
        for _ in self.cache.len()..self.rate {
            self.cache.push(Fr::zero());
        }
        // add the cache into sponge state
        for i in 0..self.rate {
            self.state[i] += self.cache[i];
        }
        self.state = self.poseidon.permutation(&self.state, 4)?;
        Ok(())
    }

    pub fn absorb(&mut self, input: Fr) -> Result<(), BlackBoxResolutionError> {
        assert!(!self.squeezed);
        if self.cache.len() == self.rate {
            // If we're absorbing, and the cache is full, apply the sponge permutation to compress the cache
            self.perform_duplex()?;
            self.cache = vec![input];
        } else {
            // If we're absorbing, and the cache is not full, add the input into the cache
            self.cache.push(input);
        }
        Ok(())
    }

    pub fn squeeze(&mut self) -> Result<Fr, BlackBoxResolutionError> {
        assert!(!self.squeezed);
        // If we're in absorb mode, apply sponge permutation to compress the cache.
        self.perform_duplex()?;
        self.squeezed = true;

        // Pop one item off the top of the permutation and return it.
        Ok(self.state[0])
    }
}

// #[derive(Clone, PartialEq, Eq, Debug, Error)]
// pub enum BlackBoxResolutionError {
//     #[error("failed to solve blackbox function: {0}, reason: {1}")]
//     Failed(acir::BlackBoxFunc, String),
// }

#[test]
fn hash_smoke_test() {
    let fields = [
        Fr::from(1u128),
        Fr::from(2u128),
        Fr::from(3u128),
        Fr::from(4u128),
    ];
    let result = poseidon_hash(&fields).expect("should hash successfully");
    assert_eq!(
        result,
        field_from_hex("130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9"),
    );

    pub fn field_from_hex(hex: &str) -> Fr {
        Fr::from_be_bytes_reduce(&hex::decode(hex).expect("Should be passed only valid hex"))
    }
}