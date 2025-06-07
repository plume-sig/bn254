//! Matches <https://github.com/signorecello/zk-nullifier-sig/blob/main/circuits/noir/src/curves/bn254.nr>
//!
//! To be finished when test vectors will be agreeing.

use std::str::FromStr;

pub use acir_field::GenericFieldElement;
pub use ark_grumpkin;
pub use ark_grumpkin::Affine;
pub use bn254_blackbox_solver::{poseidon_hash, multi_scalar_mul};
pub use acvm_blackbox_solver::BlackBoxResolutionError;
// use num_bigint::BigUint;
pub use ark_ff::{fields::{One, Zero}, Field, PrimeField, BigInteger};
use std::ops::Neg;
// use ark_serialize::CanonicalSerialize;
use types::NoirScalar;

use crate::types::{PlumeSignaturePrivate, PlumeSignaturePublic};

// for the wraper
// pub use ark_ec::CurveGroup;

// mod hash;
pub mod utils;
pub mod types;

const SQRT_NEG_3: &str = "8815841940592487684786734430012312169832938914291687956923";
const MSG_EXPECT_CONSTANT: &str = "constant";
const MSG_EXPECT_CONDITION: &str = "checked in the condition";

pub fn hash_to_curve(msg: &[u8]) -> Affine {
    // assert!(msg.len() <= u32::MAX as usize); // feels useless in reality because of verification costs, but added to mirror the original yet #u32

    let u = hash_to_field(msg);

    /* "Note: It's usually scalars Fr that are mapped to curves. Here, we're actually mapping Noir `Field` types, which are grumpkin's base field Fq elements. Grumpkin's |Fr| > |Fq| = |`Field`|."
    #frfq */
    let Q0 = map_to_curve(u.0.into_repr());
    let Q1 = map_to_curve(u.1.into_repr());

    (Q0 + Q1).into()
}

pub(crate) fn hash_to_field(msg: &[u8]) -> (GenericFieldElement<ark_grumpkin::Fq>, GenericFieldElement<ark_grumpkin::Fq>) {
    // assert!(msg.len() <= u32::MAX as usize); // feels useless in reality because of verification costs, but added to mirror the origin yet #u32
    
    let m = poseidon_hash(
        utils::pack_bytes(msg).into_iter().map(GenericFieldElement::from_repr).collect::<Vec<_>>().as_slice(), 
        // 1) the respective function `msg` arg is `[u8; N]` 2) `pack_bytes` output is monomorhic
        false
    ).expect("TODO");
    let u_0 = 
        poseidon_hash(&[m, GenericFieldElement::from_repr(ark_grumpkin::Fq::zero())], false).expect("TODO");
    let u_1 = 
        poseidon_hash(&[m, GenericFieldElement::from_repr(ark_grumpkin::Fq::one())], false).expect("TODO");
    (u_0, u_1)
}

// "Uses a more efficient method from https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf that works for BN curves"
pub(crate) fn map_to_curve(t: ark_grumpkin::Fq) -> Affine {
    let sqrt_neg_3 = ark_grumpkin::Fq::from_str(SQRT_NEG_3).expect(MSG_EXPECT_CONSTANT);
    
    let b = -ark_grumpkin::Fq::from_str("17").expect(MSG_EXPECT_CONSTANT); // "TODO: put in constants file"

    // > TODO: hard-code the constant result if t = 0 (see the recommendation for the point to use, in the paper).
    // > Having said that, it's unlikely - in the case of plume - for an input to ever be 0, so maybe it's not worth implementing that edge case?
    assert!(!t.is_zero(), "0 not yet supported");

    let t_2 = t * t;

    let zeta = (sqrt_neg_3 - ark_grumpkin::Fq::one()) / ark_grumpkin::Fq::from_str("2").expect(MSG_EXPECT_CONSTANT);
    let d = t_2 + ark_grumpkin::Fq::one() + b;
    let v = zeta - (sqrt_neg_3 * t_2) / d;
    let y = d / (sqrt_neg_3 * t);

    let x1 = v;
    let s1 = x1 * x1 * x1 + b;
    let x2 = v.neg() - ark_grumpkin::Fq::one();
    let s2 = x2 * x2 * x2 + b;
    let x3 = ark_grumpkin::Fq::one() + y * y;
    let s3 = x3 * x3 * x3 + b;

    let y1 = s1.sqrt();
    let y2 = s2.sqrt();
    let y3 = s3.sqrt();

    assert!(y1.is_some() || y2.is_some() || y3.is_some());

    // #frfq
    if y1.is_some() {
        // #[cfg(test)] return G1Affine::new_unchecked(Fq::from(x1.into_bigint()), Fq::from(y1.expect(MSG_EXPECT_CONDITION).into_bigint()));
        Affine::new(ark_grumpkin::Fq::from(x1.into_bigint()), ark_grumpkin::Fq::from(y1.expect(MSG_EXPECT_CONDITION).into_bigint()))
    } else if y2.is_some() {
        // #[cfg(test)] return G1Affine::new_unchecked(Fq::from(x2.into_bigint()), Fq::from(y2.expect(MSG_EXPECT_CONDITION).into_bigint()));
        Affine::new(ark_grumpkin::Fq::from(x2.into_bigint()), ark_grumpkin::Fq::from(y2.expect(MSG_EXPECT_CONDITION).into_bigint()))
    } else {
        // #[cfg(test)] return G1Affine::new_unchecked(Fq::from(x3.into_bigint()), Fq::from(y3.expect(MSG_EXPECT_CONDITION).into_bigint()));
        Affine::new(ark_grumpkin::Fq::from(x3.into_bigint()), ark_grumpkin::Fq::from(y3.expect(MSG_EXPECT_CONDITION).into_bigint()))
    }
}

pub fn sign_with_r(
    is_v1: bool, sk: NoirScalar, msg: &[u8], r: NoirScalar
) -> (PlumeSignaturePublic, PlumeSignaturePrivate) {todo!()}
pub fn sign(is_v1: bool, sk: NoirScalar, msg: &[u8]) -> (
    PlumeSignaturePublic, PlumeSignaturePrivate
) {todo!()}

#[cfg(test)]
/// Matches <https://github.com/signorecello/zk-nullifier-sig/blob/main/circuits/noir/src/tests/bn254.nr>
mod tests;