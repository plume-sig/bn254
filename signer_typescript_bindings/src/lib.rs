//! sadly `wasm-bindgen` doesn't support top-level @module docs yet

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use wasm_bindgen::prelude::*;

use plume_bn254::types::Zeroize;
use plume_bn254::types::NoirScalar;

#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignature - offers two things: 
/// - the public values available as an object for further manipulation, and 
/// - the secret values capable of `zeroize` and available via getters.
/// 
// TODO update when the wrapped crate stabilize #needsWrappedFinal
/// **NB** All the values are serialized via <https://docs.rs/plume_arkworks/latest/plume_arkworks/trait.CanonicalSerialize.html#method.serialize_uncompressed> for several reasons.
/// - it's the native method for the library the implementation is based on
/// - $y$ coordinate will be needed during the verification
/// - current verifier is in Noir which leans toward LE bytes as well as `arkworks`
pub struct PlumeSignature {
    /// @type PlumeSignaturePublic 
    pub instance: js_sys::Object, 
    pub witness: PlumeSignaturePrivate
}
#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignaturePublic - a wrapper around 
/// <https://docs.rs/plume_arkworks/latest/plume_arkworks/struct.PlumeSignaturePublic.html>. #needsWrappedFinal
#[derive(serde::Serialize)]
pub struct PlumeSignaturePublic {
    pub message: Vec<u8>,
    // #needsWrappedFinal
    /// [`plume_arkworks::Affine`](https://docs.rs/plume_arkworks/latest/plume_arkworks/secp256k1/curves/type.Affine.html) 
    /// is represented as an `Uint8Array` from <https://docs.rs/plume_arkworks/latest/plume_arkworks/trait.CanonicalSerialize.html#method.serialize_uncompressed>.
    pub nullifier: Vec<u8>,
    // #needsWrappedFinal
    /// [`plume_arkworks::Fr`](https://docs.rs/plume_arkworks/latest/plume_arkworks/secp256k1/fields/fr/type.Fr.html) 
    /// is represented as an `Uint8Array` from <https://docs.rs/plume_arkworks/latest/plume_arkworks/trait.CanonicalSerialize.html#method.serialize_uncompressed>.
    pub s: Vec<u8>,
    /// The optional property to help distinguish the used variant.
    pub is_v1: Option<bool>
}
#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignaturePrivate - a wrapper around 
/// <https://docs.rs/plume_arkworks/latest/plume_arkworks/struct.PlumeSignaturePrivate.html>. #needsWrappedFinal
#[derive(Clone)]
pub struct PlumeSignaturePrivate {
    // #needsWrappedFinal
    /// [`plume_arkworks::Fr`](https://docs.rs/plume_arkworks/latest/plume_arkworks/secp256k1/fields/fr/type.Fr.html) 
    /// is represented as an `Uint8Array` from <https://docs.rs/plume_arkworks/latest/plume_arkworks/trait.CanonicalSerialize.html#method.serialize_uncompressed>.
    pub digest_private: Vec<u8>,
    pub v1specific: Option<PlumeSignatureV1Fields>,
}

#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignatureV1Fields - Wrapper around 
/// [`plume_rustcrypto::PlumeSignatureV1Fields`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignatureV1Fields.html). #needsWrappedFinal 
#[derive(Clone)]
pub struct PlumeSignatureV1Fields {
    /// the point representing randomness
    pub r_point: Vec<u8>,
    pub hashed_to_curve_r: Vec<u8>,
}

#[wasm_bindgen]
impl PlumeSignature {
    #[wasm_bindgen]
    /// Zeroize the witness values from the Wasm memory.
    pub fn zeroize(&mut self) {
        self.witness.digest_private.zeroize();
        if let Some(v1) = self.witness.v1specific.as_mut() {
            v1.hashed_to_curve_r.zeroize();
            v1.r_point.zeroize();
        }
    }
}

#[wasm_bindgen(skip_jsdoc)]
/// @throws TODO #needsWrappedFinal test and describe the errors before publishing; it's like will be just the link <https://docs.rs/ark-serialize/0.5.0/ark_serialize/enum.SerializationError.html#variants>, would be nice to re-export then
/// @param {boolean} isV1 - the flag to choose between V1 and V2 output.
/// @param {Uint8Array} sk - #needsWrappedFinal the secret key: basically the little-endian (LE) [scalar](https://docs.rs/plume_arkworks/latest/plume_arkworks/secp256k1/fields/fr/type.Fr.html); the details of the byte representation are at <https://docs.rs/plume_arkworks/latest/plume_arkworks/trait.CanonicalDeserialize.html>, note that compression isn't rellevant to this type
/// @param {Uint8Array} msg
/// @returns {PlumeSignature}
pub fn sign(is_v1: bool, sk: &mut [u8], msg: &[u8]) -> Result<PlumeSignature, JsError> {
    let mut sk_z = 
        <NoirScalar as ark_serialize::CanonicalDeserialize>::deserialize_uncompressed(sk.as_ref())?;
    sk.zeroize();

    let sig = plume_bn254::sign(is_v1, sk_z, msg);
    
    sk_z.zeroize();
    // the lengthes will be different for BN254
    let mut writer_point = [0u8; 33];
    let mut writer_scalar = [0u8; 32];
    // debug_assert_eq!(2 * 32, pk_z.serialized_size(Compress::No));
    debug_assert_eq!(32, sk_z.serialized_size(Compress::No));
    let res = PlumeSignature { 
        // `witness` goes first so that `instance` do the job of "zeroizing" the writers
        witness: PlumeSignaturePrivate { 
            digest_private: {
                sig.1.digest_private.serialize_uncompressed(writer_scalar.as_mut_slice())?;
                writer_scalar.into()
            },
            v1specific: if let Some(v) = &sig.1.v1specific {
                Some(PlumeSignatureV1Fields {
                    r_point: {
                        v.r_point.serialize_uncompressed(writer_point.as_mut_slice())?;
                        writer_point.into()
                    }, 
                    hashed_to_curve_r: {
                        v.hashed_to_curve_r.serialize_uncompressed(writer_point.as_mut_slice())?;
                        writer_point.into()
                    }, 
                })
            } else { None },
        },
        instance: serde_wasm_bindgen::to_value(&PlumeSignaturePublic { 
            message: sig.0.message, 
            nullifier: {
                sig.0.nullifier.serialize_uncompressed(writer_point.as_mut_slice())?;
                writer_point.into()
            }, 
            s: {
                sig.0.s.serialize_uncompressed(writer_scalar.as_mut_slice())?;
                writer_scalar.into()
            },
            is_v1: Some(is_v1)
        })?.into(), 
    };
    // pk_z.zeroize();
    Ok(res)
}

#[wasm_bindgen(js_name = sec1DerScalarToBigint)]
/// This might leave the values in the memory! Don't use for the private values.
/// 
/// JS most native format for a scalar is `BigInt`, but it's not really transportable or secure, so for uniformity of the approach `s` in the public part of `PlumeSignature` is defined similar 
/// to `digest_private`; but if you want to have it as a `BigInt` you can use this utility.
pub fn scalar_to_bigint(scalar: &[u8]) -> Result<js_sys::BigInt, JsError> {
    Ok(js_sys::BigInt::new(&JsValue::from_str(
        NoirScalar::deserialize_uncompressed(scalar)?.to_string().as_str()
    ))
    // TODO Test the utility on a `s` value in TS. Update the `expect`.
    .expect(
        "`BigInt` always can be created from hex string, and `v.to_string()` always produce that",
    ))
}
