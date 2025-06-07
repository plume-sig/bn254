use std::str::FromStr;

use ark_bn254::G1Affine;
pub use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_ff::fields::{One, Zero};

pub fn form_plume_msg(msg: &[u8], pk: &G1Affine) -> Vec<u8> {
    [msg, compress_ec_point(pk).as_slice()].concat()
}

/// https://github.com/signorecello/zk-nullifier-sig/blob/9e6c08d90fc9b18d748e037a6a2667c78f63acca/circuits/noir/src/utils/mod.nr#L89
pub(crate) fn hash_to_curve_bn254(msg: [u8; 41]) -> G1Affine {
    let grumpki = super::hash_to_curve(&msg);
    G1Affine { 
        x: ark_grumpkin::Fr::from(grumpki.x.into_bigint()), 
        y: ark_grumpkin::Fr::from(grumpki.y.into_bigint()), 
        infinity: ark_ec::AffineRepr::is_zero(&grumpki) 
    }
}

pub fn pack_bytes(bytes: &[u8]) -> Vec<ark_grumpkin::Fq> {
    let n = bytes.len();
    // assert!(n <= u32::MAX as usize); // feels useless in reality because of verification costs, but added to mirror the origin yet #u32
    let len_result = n / 31 + 1;
    
    let mut bytes_padded = bytes.to_vec();
    bytes_padded.extend([0].repeat(31 * len_result - n));
    let mut res = Vec::with_capacity(len_result);
    for i in 0..len_result {
        let start = i * 31;
        res.push(field_from_bytes(&bytes_padded[start..start + 31]));
    }
    assert_eq!(res.len(), len_result);
    res
}

fn field_from_bytes(bytes: &[u8]) -> ark_grumpkin::Fq {
    let n = bytes.len();
    assert!(n < 32, "field_from_bytes: N must be less than 32"); // #u32

    let offset_multiplier = ark_grumpkin::Fq::from_str("256").expect(super::MSG_EXPECT_CONSTANT);

    let mut as_field = ark_grumpkin::Fq::zero();
    let mut offset = ark_grumpkin::Fq::one();
    for i in 0..n {
        as_field += ark_grumpkin::Fq::from(bytes[i]) * offset;
        offset *= &offset_multiplier;
    }
    as_field
}

// `serialize_compressed` produce different output, so it's smoother just to take the `fn` from Aztec for now
pub(crate) fn compress_ec_point(point: &G1Affine) -> [u8; 33] {
    let x_bn = point.x().expect("TODO");
    let mut x: [u8; 32] = x_bn.into_bigint().to_bytes_le().try_into().expect("TODO");

    let y_bn = point.y().expect("TODO").into_bigint();
    let sign = y_bn.to_bytes_le()[0] & 1;
    x.reverse();
    [[sign + 2].as_slice(), &x].concat().try_into().expect("TODO")
}