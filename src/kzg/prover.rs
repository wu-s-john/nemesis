use ark_ec::Group;
use ark_ff::Field;
use ark_poly::Polynomial;

pub mod prover {
    use std::ops::Div;

    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};

    use crate::kzg::{KZGProof, CRS};

    use super::*;

    pub fn prover_commit<F, G, P>(crs: &CRS<G>, polynomial: &P) -> G
    where
        F: Field,
        G: Group<ScalarField = F>,
        P: DenseUVPolynomial<F>,
    {
        polynomial
            .coeffs()
            .iter()
            .zip(crs.g1_powers.iter())
            .map(|(coeff, g1_power)| g1_power.mul(*coeff))
            .sum()
    }

    // Unfortunately forced to use a concrete implementation of dense polynomial
    pub fn prover_open<F, G1>(
        crs: &CRS<G1>,
        polynomial: &DensePolynomial<F>,
        challenge_point: &F,
        commitment: &G1,
    ) -> KZGProof<F, G1>
    where
        F: Field,
        G1: Group<ScalarField = F>,
    {
        let mut quotient_poly = polynomial.clone();

        // Create a polynomial expression for f(X) - f(z)
        // where f(X) is the original polynomial and z is the challenge point

        let eval_at_challenge = polynomial.evaluate(challenge_point);
        let constant_poly = DensePolynomial::from_coefficients_vec(vec![-eval_at_challenge]);
        quotient_poly = &quotient_poly - &constant_poly;

        // Divide by (X - z)
        let divisor = DenseUVPolynomial::from_coefficients_vec(vec![-*challenge_point, F::one()]);
        let quotient = quotient_poly.div(&divisor); // The quotient should not have a remainder doing this division

        let kzgproof = KZGProof {
            commitment: *commitment,
            challenge: *challenge_point,
            challenge_evaluation: crs.g1_powers[0].mul(eval_at_challenge),
            witness: prover_commit(crs, &quotient),
        };
        kzgproof
    }
}