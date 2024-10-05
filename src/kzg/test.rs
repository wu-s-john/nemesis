#![allow(unused_imports)]

use ark_ec::{pairing::Pairing, Group};
use ark_ff::Field;
use ark_poly::Polynomial;

use super::{CRSGenerator, CRS};

/// A struct for testing purposes that implements the CRSGenerator trait
pub struct TestCRSGenerator<F: Field, G: Group<ScalarField = F>> {
    pub generator: G,
    pub point: F,
}

impl<F: Field, G: Group<ScalarField = F>> CRSGenerator<F, G> for TestCRSGenerator<F, G> {
    fn generate(&self, degree: usize) -> CRS<G> {
        let g1_powers: Vec<G> = (0..=degree)
            .map(|i| {
                let exponent = self.point.pow(&[i as u64]);
                self.generator.mul(exponent)
            })
            .collect();

        CRS { g1_powers }
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use crate::{kzg::{prover::prover, system::{KZGSystemImpl, KZGVerifierChallenger}, verifier::verifier, KZGSystem}, util::VerifierChallenge};

    use super::*;
    use ark_bls12_381::{Bls12_381, Fr as F, G1Projective as G, G1Projective as G1, G2Projective as G2};
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_ff::UniformRand;
    use ark_poly::{polynomial::univariate::DensePolynomial, DenseUVPolynomial};
    use ark_std::rand::thread_rng;

    fn verify_prover_commit_equals_to_g_pow_valuation_point<F, G, P>(
        polynomial: &P,
        evaluation_point: F,
    ) where
        F: Field,
        G: Group<ScalarField = F>,
        P: DenseUVPolynomial<F>,
    {
        // Generate a random generator
        let mut rng = thread_rng();
        let generator = G::rand(&mut rng);
        // Create TestCRSGenerator with the random generator
        let crs_generator = TestCRSGenerator {
            generator,
            point: evaluation_point,
        };

        // Generate CRS for the degree of the polynomial
        let crs = crs_generator.generate(polynomial.degree());
        // Assert that the size of CRS is equal to polynomial degree + 1
        assert_eq!(
            crs.g1_powers.len(),
            polynomial.degree() + 1,
            "CRS size should be equal to polynomial degree + 1"
        );

        // Compute the commitment
        let commitment = prover::prover_commit(&crs, polynomial);

        // Compute f(evaluation_point)
        let f_of_point = polynomial.evaluate(&evaluation_point);

        // Compute g^(f(evaluation_point))
        let expected_commitment = generator.mul(f_of_point);

        // Assert that the computed commitment equals g^(f(evaluation_point))
        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn run_test_prover_commit() {
        // Create the polynomial x^3 + x - x^2 - 1
        let polynomial = DensePolynomial::from_coefficients_vec(vec![
            -F::from(1u64), // constant term
            F::from(1u64),  // x^1 coefficient
            -F::from(1u64), // x^2 coefficient
            F::from(1u64),  // x^3 coefficient
        ]);

        verify_prover_commit_equals_to_g_pow_valuation_point::<F, G, DensePolynomial<F>>(
            &polynomial,
            F::from(2u64),
        );
    }

    fn verify_prover_open_equals_to_g_pow_quotient_polynomial<F, G: PartialEq>(
        polynomial: &DensePolynomial<F>,
        quotient_polynomial: &DensePolynomial<F>,
        evaluation_point: F,
        challenge_point: F,
    ) where
        F: Field,
        G: Group<ScalarField = F>,
    {
        let mut rng = thread_rng();
        let generator = G::rand(&mut rng);

        // Setup CRS
        let crs_generator = TestCRSGenerator {
            generator,
            point: evaluation_point,
        };
        let crs = crs_generator.generate(polynomial.degree());

        // Compute the commitment
        let commitment = prover::prover_commit(&crs, polynomial);
        // Compute the witness
        let proof = prover::prover_open(&crs, polynomial, &challenge_point, &commitment);

        // Verify that the witness equals to g^(q(evaluation_point))
        let q_of_evaluation_point = quotient_polynomial.evaluate(&evaluation_point);
        let expected_witness = generator.mul(q_of_evaluation_point);

        assert_eq!(
            proof.witness, expected_witness,
            "Witness should equal g^(q(evaluation_point))"
        );
        assert_eq!(
            proof.challenge_evaluation,
            generator.mul(polynomial.evaluate(&challenge_point)),
            "Evaluation should equal g^(q(evaluation_point))"
        );
    }

    #[test]
    fn run_test_prover_open() {
        // Create the polynomial x^3 + x - x^2 - 1
        let polynomial = DensePolynomial::from_coefficients_vec(vec![
            -F::from(1u64), // constant term
            F::from(1u64),  // x^1 coefficient
            -F::from(1u64), // x^2 coefficient
            F::from(1u64),  // x^3 coefficient
        ]);

        // Suppose that the challenge point is 2 -> p(2) = 2^3 + 2 - 2^2 - 1 = 5

        // Prover will compute the quotient polynomial q(x) = (f(x) - f(2)) / (x - 2)
        // q(x) = (x^3 + x - x^2 - 1 - 5) / (x - 2) = x^2 + x + 3
        let challenge_point = F::from(2u64);

        // We want to verify that the prover's witness equals to g^(q(2))
        // q(2) = 2^2 + 2 + 3 = 7

        let quotient_polynomial = DensePolynomial::from_coefficients_vec(vec![
            F::from(3u64),
            F::from(1u64),
            F::from(1u64),
        ]);
        verify_prover_open_equals_to_g_pow_quotient_polynomial::<F, G>(
            &polynomial,
            &quotient_polynomial,
            F::from(3u64),
            challenge_point,
        );
    }

    #[test]
    fn test_prover_verifier_interaction() {
        let mut rng = thread_rng();

        // Create the polynomial x^3 + x - x^2 - 1
        let polynomial = DensePolynomial::from_coefficients_vec(vec![
            -F::from(1u64), // constant term
            F::from(1u64),  // x^1 coefficient
            -F::from(1u64), // x^2 coefficient
            F::from(1u64),  // x^3 coefficient
        ]);

        // Set up the CRS
        let evaluation_point = F::from(3u64);
        let g1 = G1::rand(&mut rng);
        let g2 = G2::rand(&mut rng);
        let crs_generator = TestCRSGenerator {
            generator: g1,
            point: evaluation_point,
        };
        let crs = crs_generator.generate(polynomial.degree());

        // Prover: Create commitment
        let commitment = prover::prover_commit::<F, G1, DensePolynomial<F>>(&crs, &polynomial);

        // Verifier: Generate challenge
        let challenge_point = F::from(2u64);

        // Prover: Generate proof
        let proof = prover::prover_open(&crs, &polynomial, &challenge_point, &commitment);

        // Print out s - challenge
        let s_minus_challenge = evaluation_point - challenge_point;
        

        // Compute g_2^(s - challenge)
        let g_s_minus_challenge = g2 * s_minus_challenge;


        // Printing some debug logs
        println!("s - challenge = {:?}", s_minus_challenge);
        println!("g^(s - challenge) = {:?}", g_s_minus_challenge);
        
        // Compute f(s) manually
        let f_s = polynomial.evaluate(&evaluation_point);
        
        // Compute g1^f(s)
        let g1_f_s = g1 * f_s;

        // Print out the computed values
        println!("Manually computed f(s) = {:?}", f_s);
        println!("Manually computed g1^f(s) = {:?}", g1_f_s);
        println!("Commitment = {:?}", commitment);

        // Verify that the manually computed g1^f(s) matches the commitment
        assert_eq!(g1_f_s, commitment, "Manually computed g1^f(s) should equal the commitment");


        // Compute f(challenge)
        let f_challenge = polynomial.evaluate(&challenge_point);
        
        // Compute g1^f(challenge)
        let g1_f_challenge = g1 * f_challenge;

        // Print out the computed values
        println!("f(challenge) = {:?}", f_challenge);
        println!("g1^f(challenge) = {:?}", g1_f_challenge);

        println!("verify: commitment - g_1^(-y) = {:?}", commitment - g1_f_challenge);


        println!("=================\n");

        // Verifier: Verify the proof
        let g2_s = g2 * evaluation_point;
        let result = verifier::verify::<Bls12_381>(proof, challenge_point, g2, g2_s);

        assert!(result, "Verification should succeed");
    }


        #[test]
        #[ignore]
        fn test_kzg_system_prove_verify() {
            // Set up the KZG system
            let rng = &mut thread_rng();
            let degree = 10;
            
            // Use TestCRSGenerator
            let generator = G1::rand(rng);
            let point = F::rand(rng);
            let crs_generator = TestCRSGenerator { generator, point };
            let crs = crs_generator.generate(degree);
        
            let g2 = G2::rand(rng);
            let s = F::rand(rng);
            let g2_s = g2 * s;
        
            // Create a PoseidonConfig for the verifier challenger
            let poseidon_config = PoseidonConfig::<F>::new(8, 57, 5, vec![vec![F::from(1u64); 3]; 3], vec![vec![F::from(0u64); 3]; 65], 2, 1);
            let verifier_challenger = KZGVerifierChallenger::new(poseidon_config);
        
            let system = KZGSystemImpl {
                crs,
                degree,
                g2,
                g2_s,
                verifier_challenge: verifier_challenger,
            };
        
            // Generate a random polynomial
            let polynomial = DensePolynomial::<F>::rand(degree, rng);
        
            // Prove
            let proof = system.prove(&polynomial);
        
            // Verify
            let result = system.verify(proof);
        
            assert!(result, "Verification should succeed for a valid proof");
        }

}