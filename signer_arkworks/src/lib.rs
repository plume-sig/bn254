use std::str::FromStr;

pub use acir_field::GenericFieldElement;
use ark_bn254::G1Affine;
pub use ark_grumpkin::Fq;
use ark_grumpkin::Affine;
pub use bn254_blackbox_solver::{poseidon_hash, multi_scalar_mul};
pub use acvm_blackbox_solver::BlackBoxResolutionError;
// use num_bigint::BigUint;
pub use ark_ff::{fields::{One, Zero}, Field, PrimeField, BigInteger};
use std::ops::Neg;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;

// mod hash;

const SQRT_NEG_3: &str = "8815841940592487684786734430012312169832938914291687956923";
const MSG_EXPECT_CONSTANT: &str = "constant";
const MSG_EXPECT_CONDITION: &str = "checked in the condition";

pub fn hash_to_curve(msg: &[u8]) -> Affine {
    assert!(msg.len() <= u32::MAX as usize); // feels useless in reality because of verification costs, but added to mirror the origin yet #u32

    let u = hash_to_field(msg);

    /* "Note: It's usually scalars Fr that are mapped to curves. Here, we're actually mapping Noir `Field` types, which are grumpkin's base field Fq elements. Grumpkin's |Fr| > |Fq| = |`Field`|."
    #frfq */
    let Q0 = map_to_curve(u.0.into_repr());
    let Q1 = map_to_curve(u.1.into_repr());

    (Q0 + Q1).into()
}

pub(crate) fn hash_to_curve_bn254(msg: [u8; 41]) -> G1Affine {
    let grumpki = hash_to_curve(&msg);
    G1Affine { x: ark_grumpkin::Fr::from(grumpki.x.into_bigint()), y: ark_grumpkin::Fr::from(grumpki.y.into_bigint()), infinity: grumpki.is_zero() }
}

// "Uses a more efficient method from https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf that works for BN curves"
pub(crate) fn map_to_curve(t: Fq) -> Affine {
    let sqrt_neg_3 = Fq::from_str(SQRT_NEG_3).expect(MSG_EXPECT_CONSTANT);
    
    let b = -Fq::from_str("17").expect(MSG_EXPECT_CONSTANT); // "TODO: put in constants file"

    // > TODO: hard-code the constant result if t = 0 (see the recommendation for the point to use, in the paper).
    // > Having said that, it's unlikely - in the case of plume - for an input to ever be 0, so maybe it's not worth implementing that edge case?
    assert!(!t.is_zero(), "0 not yet supported");

    let t_2 = &t * &t;

    let zeta = (&sqrt_neg_3 - &Fq::one()) / Fq::from_str("2").expect(MSG_EXPECT_CONSTANT);
    let d = &t_2 + &Fq::one() + b;
    let v = zeta - (&sqrt_neg_3 * &t_2) / &d;
    let y = d / (sqrt_neg_3 * t);

    let x1 = v.clone();
    let s1 = &x1 * &x1 * &x1 + &b;
    let x2 = &v.neg() - &Fq::one();
    let s2 = &x2 * &x2 * &x2 + &b;
    let x3 = Fq::one() + &y * &y;
    let s3 = &x3 * &x3 * &x3 + &b;

    let y1 = s1.sqrt();
    let y2 = s2.sqrt();
    let y3 = s3.sqrt();

    assert!(y1.is_some() || y2.is_some() || y3.is_some());

    // #frfq
    if y1.is_some() {
        // #[cfg(test)] return G1Affine::new_unchecked(Fq::from(x1.into_bigint()), Fq::from(y1.expect(MSG_EXPECT_CONDITION).into_bigint()));
        Affine::new(Fq::from(x1.into_bigint()), Fq::from(y1.expect(MSG_EXPECT_CONDITION).into_bigint()))
    } else if y2.is_some() {
        // #[cfg(test)] return G1Affine::new_unchecked(Fq::from(x2.into_bigint()), Fq::from(y2.expect(MSG_EXPECT_CONDITION).into_bigint()));
        Affine::new(Fq::from(x2.into_bigint()), Fq::from(y2.expect(MSG_EXPECT_CONDITION).into_bigint()))
    } else {
        // #[cfg(test)] return G1Affine::new_unchecked(Fq::from(x3.into_bigint()), Fq::from(y3.expect(MSG_EXPECT_CONDITION).into_bigint()));
        Affine::new(Fq::from(x3.into_bigint()), Fq::from(y3.expect(MSG_EXPECT_CONDITION).into_bigint()))
    }
}

pub(crate) fn hash_to_field(msg: &[u8]) -> (GenericFieldElement<Fq>, GenericFieldElement<Fq>) {
    assert!(msg.len() <= u32::MAX as usize); // feels useless in reality because of verification costs, but added to mirror the origin yet #u32
    
    let m = poseidon_hash(
        pack_bytes(msg).into_iter().map(|x| GenericFieldElement::from_repr(x)).collect::<Vec<_>>().as_slice(), 
        /// 1) the respective function `msg` arg is `[u8; N]` 2) `pack_bytes` output is monomorhic
        false
    ).expect("TODO");
    let u_0 = 
        poseidon_hash(&[m, GenericFieldElement::from_repr(Fq::zero())], false).expect("TODO");
    let u_1 = 
        poseidon_hash(&[m, GenericFieldElement::from_repr(Fq::one())], false).expect("TODO");
    (u_0, u_1)
}

pub fn pack_bytes(bytes: &[u8]) -> Vec<Fq> {
    let n = bytes.len();
    assert!(n <= u32::MAX as usize); // feels useless in reality because of verification costs, but added to mirror the origin yet #u32
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

fn field_from_bytes(bytes: &[u8]) -> Fq {
    let n = bytes.len();
    assert!(n < 32, "field_from_bytes: N must be less than 32"); // #u32

    let offset_multiplier = Fq::from_str("256").expect(MSG_EXPECT_CONSTANT);

    let mut as_field = Fq::zero();
    let mut offset = Fq::one();
    for i in 0..n {
        as_field += Fq::from(bytes[i]) * offset;
        offset *= &offset_multiplier;
    }
    as_field
}

pub struct Plume {
    msg: Vec<u8>,
    c: ark_grumpkin::Fq,
    s: ark_grumpkin::Fq,
    pk: G1Affine,
    nullifier: G1Affine,
    // hash_to_curve: fn([u8; L + COMPRESSED_SIZE_BYTES]) -> BigCurve<BN, CurveParams>,
}
impl Plume {
    fn check_ec_equations(
        self,
    ) -> (G1Affine, G1Affine, G1Affine, ) {
        let s_point = (
                <ark_bn254::g1::Config as ark_ec::short_weierstrass::SWCurveConfig>::GENERATOR 
            // Affine::new_unchecked(1.into(), 2.into()).mul_bigint(
                // self.s.into_bigint()
                * self.s
            ).into_affine();
        // here's the place it doesn't make sense to match further!
        let pkc = (self.pk * self.c).into_affine();
        dbg!(pkc.x.into_bigint().to_bytes_le());
        let r_point = (s_point - self.pk * self.c).into_affine();
        dbg!(s_point.x.into_bigint().to_bytes_le());

        let plume_msg = self.form_plume_msg();
        let hashed_to_curve = hash_to_curve_bn254(plume_msg.try_into().expect("TODO"));
        dbg!(hashed_to_curve.xy().unwrap().1.into_bigint().to_bytes_le());
        let h_pow_s = hashed_to_curve * self.s;
        let hashed_to_curve_r = (h_pow_s - self.nullifier * self.c).into();

        (r_point, hashed_to_curve_r, hashed_to_curve)
    }

    fn form_plume_msg(&self) -> Vec<u8> {
        [self.msg.clone(), compress_ec_point(&self.pk).into()].concat()
    }
}
// `serialize_compressed` produce different output, so it's smoother just to take the `fn` from Aztec for now
fn compress_ec_point(point: &G1Affine) -> [u8; 33] {
    let x_bn = point.x().expect("TODO");
    let mut x: [u8; 32] = x_bn.into_bigint().to_bytes_le().try_into().expect("TODO");

    let y_bn = point.y().expect("TODO").into_bigint();
    let sign = y_bn.to_bytes_le()[0] & 1;
    x.reverse();
    [[sign + 2].as_slice(), &x].concat().try_into().expect("TODO")
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use acir_field::AcirField;
    use ark_ec::CurveGroup;
    use ark_ff::{BigInteger, ToConstraintField};

    use super::*;

    fn poseidon2_points(points: &[Affine]) -> GenericFieldElement<Fq> {
        let n = points.len();
        let two_n = 2 * n;
        // let points = points.iter().map(|p| p.xy()).collect();
        // let input = [points.]
        let mut input = Vec::with_capacity(two_n);
        // let mut input_y = Vec::with_capacity(n);
        for p in points {
            let xy = p.xy().unwrap();
            // #frfq 
            input.push(GenericFieldElement::from_repr(Fq::from(xy.0.into_bigint())));
            input.push(GenericFieldElement::from_repr(Fq::from(xy.1.into_bigint())));
            // input.push(GenericFieldElement::from_repr(xy.0));
            // input.push(GenericFieldElement::from_repr(xy.1));
        }
        input.iter().for_each(|e| {println!("{:?}", e.to_le_bytes());});
        // assert_eq!(two_n, input.len());
        let res = poseidon_hash(&input[0..n], true).unwrap();
        dbg!(res.to_le_bytes());
        res
        // "Compressing the points costs a fortune because of the check for each point that y < (p-1)/2 (each comparison costs ~190 gates)."
        // `poseidon2_hash(compress_points::<_, N_PLUS_1>(points))`
    }
    
    #[test]
    fn test_plume_v2_bn254() {
        let msg: [u8; 8] = [115, 105, 103, 110, 84, 104, 105, 115];

        // let sk_f = 0x1234;

        let sk = ark_grumpkin::Fr::from(0x1234);
        // let sk_n: ScalarWithOps = field_to_bignum_unsafe(sk_f);
        // let r_n: ScalarWithOps = BN254Fq::from_slice([0x1234, 0x1234, 0x12]);
        let r = 
            ark_grumpkin::Fr::from_le_bytes_mod_order(
                // Fq::from_le_bytes_mod_order(
                    &[52, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0]
                // ).into_bigint();
            );
        // let r: Scalar = bignum_to_scalar(r_n);

        let G = 
            // G1Affine::new_unchecked(
            ark_grumpkin::Affine::new(
                1.into(), 
                ark_grumpkin::Fq::from_str("17631683881184975370165255887551781615748388533673675138860").unwrap()
            );
        
        let pk = (G * &sk).into_affine();
        let (g_x, g_y) = G.xy().unwrap();
        // let pk = multi_scalar_mul(&[g_x, g_y, Fr::zero().into()], scalars_lo, scalars_hi, pedantic_solving)
        let (pk_x, pk_y) = pk.xy().unwrap();
        let H = hash_to_curve(dbg!([
            // msg.as_slice(), 
            &[msg[0]].repeat(msg.len()),
            &dbg!(pk_x.into_bigint().to_bytes_le())[0..1],
            &pk_y.into_bigint().to_bytes_le()[0..1]
        ].concat()).as_slice());

        let nullifier: Affine = (H * &sk).into();

        let rG: Affine = (G * r).into();
        let rH: Affine = (H * r).into();

        let A = pk;
        let B = nullifier;
        let A2 = rG;
        let B2 = rH;

        let c = poseidon2_points(&[G, H, A, B, A2, B2]).into_repr();
        // let c_n: ScalarWithOps = field_to_bignum_unsafe(c_f);
        let c_n = ark_grumpkin::Fr::from(c.into_bigint());
        dbg!(c.into_bigint().to_bytes_le());

        // let sk_n = Fq::from(sk.into_bigint());
        // let r_n = Fq::from(r.into_bigint());
        let s_n = //ark_grumpkin::Fr::from(
            r + (sk * c_n);//).into_bigint()
        // );
        let s = ark_grumpkin::Fq::from(s_n.into_bigint());

        let pk = G1Affine { x: ark_grumpkin::Fr::from(pk.x.into_bigint()), y: ark_grumpkin::Fr::from(pk.y.into_bigint()), infinity: pk.is_zero() };
        dbg!(pk.x().unwrap().into_bigint().to_bytes_le());
        let nullifier = G1Affine { x: ark_grumpkin::Fr::from(nullifier.x.into_bigint()), y: ark_grumpkin::Fr::from(nullifier.y.into_bigint()), infinity: nullifier.is_zero() };
        
        let plume = Plume{msg: msg.into(), c: c, s, pk, nullifier};
        // let (_, _, ..) = plume.check_ec_equations();
        let (rp, hashed_r, ..) = plume.check_ec_equations();
        dbg!(
            rp.x().unwrap().into_bigint().to_bytes_le(),
            hashed_r.xy().unwrap().1.into_bigint().to_bytes_le(),
        );
    }
}
