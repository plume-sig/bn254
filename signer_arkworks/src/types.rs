pub use ark_bn254::{Fr as NoirScalar, G1Affine};
pub use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

/// PLUME signature instance
#[derive(Clone, Debug)]
pub struct PlumeSignaturePublic {
    pub message: Vec<u8>,
    pub s: NoirScalar,
    /// The nullifier.
    pub nullifier: G1Affine,
    pub is_v1: Option<bool>,
}
/// PLUME signature witness. Store securely and choose which data from the public part you will use to identify this part.
/// 
/// `v1specific` field differintiate whether V1 or V2 protocol will be used.
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct PlumeSignaturePrivate {
    pub digest_private: NoirScalar,
    /// Signature data for V1 signatures.
    pub v1specific: Option<PlumeSignatureV1Fields>,
}
/// Nested `struct` holding additional signature data used in variant 1 of the protocol.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct PlumeSignatureV1Fields {
    /// The randomness `r` represented as the curve point.
    pub r_point: G1Affine,
    /// The hash-to-curve output multiplied by the random `r`.  
    pub hashed_to_curve_r: G1Affine,
}