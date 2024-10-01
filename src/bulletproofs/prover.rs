use ark_ec::Group;
use ark_ff::Field;
use super::helpers::*;
use crate::bulletproofs::traits::{BulletproofGenerators, BulletproofProofSmall, BulletproofRecProof};

pub mod prover {
    use super::*;

    pub fn prove_rec<S: Field, G: Group<ScalarField = S>>(
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> BulletproofRecProof<S, G> {
        let n = v1.len();
        assert_eq!(n, v2.len(), "Input vectors must have the same length");

        let m = n / 2;

        let (a_l, a_r) = v1.split_at(m);
        let (b_l, b_r) = v2.split_at(m);
        let (g_l, g_r) = generators.g.split_at(m);
        let (h_l, h_r) = generators.h.split_at(m);
        // Assert that all splits are of equal size
        assert_eq!(a_l.len(), a_r.len(), "a_l and a_r must have the same length");
        assert_eq!(b_l.len(), b_r.len(), "b_l and b_r must have the same length");
        assert_eq!(g_l.len(), g_r.len(), "g_l and g_r must have the same length");
        assert_eq!(h_l.len(), h_r.len(), "h_l and h_r must have the same length");

        // Compute L = [<a_L, b_R>]U + [a_L]G_R + [b_R]H_L
        let l_value = compute_intermediate_commitment(a_l, b_r, &generators.u, g_r, h_l);

        // Compute R = [<a_R, b_L>]U + [a_R]G_L + [b_L]H_R
        let r_value = compute_intermediate_commitment(a_r, b_l, &generators.u, g_l, h_r);

        let dot_product = compute_dot_product(&v1, &v2);

        let pedersen_commitment = compute_pedersen_commitment(&v1, &v2, dot_product, &generators.g, &generators.h, &generators.u);

        BulletproofRecProof {
            dot_product,
            pedersen_commitment,
            l_value,
            r_value,
        }
    }

    pub fn prove_small<S: Field, G: Group<ScalarField = S>>(
        x1: S,
        x2: S,
        g1: G,
        g2: G,
        u: G,
    ) -> BulletproofProofSmall<S, G> {
        BulletproofProofSmall {
            value1: x1,
            value2: x2,
            dot_product: x1 * x2,
            pedersen_commitment: g1.mul(x1) + g2.mul(x2) + u.mul(x1 * x2),
        }
    }
}