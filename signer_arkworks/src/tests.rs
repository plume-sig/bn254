use ark_bn254::G1Affine;
use ark_ff::PrimeField;

use std::io::Read;

use acir_field::{AcirField, GenericFieldElement};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, ToConstraintField};
use ark_grumpkin::Affine;

use super::*;

fn check_ec_equations(
    self_msg: Vec<u8>,
    self_c: ark_bn254::Fr,
    self_s: ark_bn254::Fr,
    self_pk: G1Affine,
    self_nullifier: G1Affine,
) -> (G1Affine, G1Affine, G1Affine, ) {
    let s_point = (
            <ark_bn254::g1::Config as ark_ec::short_weierstrass::SWCurveConfig>::GENERATOR 
        // Affine::new_unchecked(1.into(), 2.into()).mul_bigint(
            // self.s.into_bigint()
            * self_s
        ).into_affine();
    // here's the place it doesn't make sense to match further!
    let pkc = (self_pk * self_c).into_affine();
    dbg!(pkc.x.into_bigint().to_bytes_le());
    let r_point = (s_point - self_pk * self_c).into_affine();
    dbg!(s_point.x.into_bigint().to_bytes_le());

    let plume_msg = crate::utils::form_plume_msg(&self_msg, &self_pk);
    let hashed_to_curve = crate::utils::hash_to_curve_bn254(plume_msg.try_into().expect("TODO"));
    dbg!(ark_ec::AffineRepr::xy(&hashed_to_curve).unwrap().1.into_bigint().to_bytes_le());
    let h_pow_s = hashed_to_curve * self_s;
    let hashed_to_curve_r = (h_pow_s - self_nullifier * self_c).into();

    (r_point, hashed_to_curve_r, hashed_to_curve)
}

fn poseidon2_points(points: &[Affine]) -> GenericFieldElement<ark_grumpkin::Fq> {
    let n = points.len();
    let two_n = 2 * n;
    // let points = points.iter().map(|p| p.xy()).collect();
    // let input = [points.]
    let mut input = Vec::with_capacity(two_n);
    // let mut input_y = Vec::with_capacity(n);
    for p in points {
        let xy = p.xy().unwrap();
        // #frfq 
        input.push(GenericFieldElement::from_repr(ark_grumpkin::Fq::from(xy.0.into_bigint())));
        input.push(GenericFieldElement::from_repr(ark_grumpkin::Fq::from(xy.1.into_bigint())));
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
    
    // let plume = Plume{msg: msg.into(), c: c, s, pk, nullifier};
    let plume = (msg.to_vec(), c, s, pk, nullifier);
    // let (_, _, ..) = plume.check_ec_equations();
    let (rp, hashed_r, ..) = check_ec_equations(
        plume.0, plume.1, plume.2, plume.3, plume.4
    );
    dbg!(
        rp.x().unwrap().into_bigint().to_bytes_le(),
        hashed_r.xy().unwrap().1.into_bigint().to_bytes_le(),
    );
}