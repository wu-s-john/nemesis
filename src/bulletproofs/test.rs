#![allow(unused_imports)]
#![allow(dead_code)]

use ark_ec::Group;
use ark_ff::{Field, UniformRand};
use ark_bls12_381::{Fr as Scalar, G1Projective as G1};
use ark_std::rand::thread_rng;
use crate::bulletproofs::helpers::{compute_dot_product, compute_pedersen_commitment, prove_update};

use crate::bulletproofs::{
    prover::prover,
    system::BulletproofSystemImpl,
    verifier::verifier,
    verifier_challenger::{BulletproofVerifierChallenge, VerifierChallenger},
};

use super::{BulletproofGenerators, BulletproofRecProof, BulletproofSystem};

pub struct ConstantChallenger<S: Field + Clone> {
    constant: S,
}

impl<S, G> VerifierChallenger<S, G> for ConstantChallenger<S>
where
    S: Field + Clone,
    G: Group<ScalarField = S> + Clone,
{
    fn generate_challenge(&self, _proof: &BulletproofRecProof<S, G>) -> S {
        self.constant.clone()
    }
}

fn setup_system(constant: Scalar) -> BulletproofSystemImpl::<Scalar, G1, ConstantChallenger<Scalar>> {
    BulletproofSystemImpl::<Scalar, G1, ConstantChallenger<Scalar>> {
        challenger: ConstantChallenger { constant },
        _phantom: std::marker::PhantomData,
    }
}

fn generate_random_vectors(size: usize) -> (Vec<Scalar>, Vec<Scalar>) {
    let mut rng = thread_rng();
    let v1: Vec<Scalar> = (0..size).map(|_| Scalar::rand(&mut rng)).collect();
    let v2: Vec<Scalar> = (0..size).map(|_| Scalar::rand(&mut rng)).collect();
    (v1, v2)
}

fn setup_generators(size: usize) -> BulletproofGenerators<G1> {
    let mut rng = thread_rng();
    BulletproofGenerators {
        g: (0..size).map(|_| G1::rand(&mut rng)).collect(),
        h: (0..size).map(|_| G1::rand(&mut rng)).collect(),
        u: G1::rand(&mut rng),
    }
}


#[test]
fn test_prove_verify_rec_one_round() {
    let mut rng = thread_rng();

    // Generate random vectors of size 4
    let v1 = vec![
        Scalar::from(2u64),
        Scalar::from(4u64),
        Scalar::from(6u64),
        Scalar::from(8u64),
    ];
    let v2 = vec![
        Scalar::from(2u64),
        Scalar::from(4u64),
        Scalar::from(8u64),
        Scalar::from(16u64),
    ];

    // Setup generators
    let generators = BulletproofGenerators {
        g: (0..4).map(|_| G1::rand(&mut rng)).collect(),
        h: (0..4).map(|_| G1::rand(&mut rng)).collect(),
        u: G1::rand(&mut rng),
    };

    // Prove
    let proof = prover::prove_rec(generators.clone(), v1.clone(), v2.clone());

    // Generate challenge
    let challenger = ConstantChallenger { constant: Scalar::from(2) };
    let challenge = challenger.generate_challenge(&proof);

    // We should now be able to compute the pedersen commitment
    let (new_generators, new_v1, new_v2) = prove_update(BulletproofVerifierChallenge { random_challenge: challenge }, generators, v1.clone(), v2.clone());

    // Compute expected values for new_v1 and new_v2
    let x = challenge;
    let x_inv = x.inverse().expect("Challenge should be non-zero");

    // Now check if the new_v1 and new_v2 match the expected values
    let computed_v1 = vec![Scalar::from(7u64), Scalar::from(12u64)];
    assert_eq!(new_v1, computed_v1, "new_v1 does not match the expected calculated values [7, 12]");

    let expected_v1 = vec![
        v1[0] * x + v1[2] * x_inv,
        v1[1] * x + v1[3] * x_inv,
    ];
    assert_eq!(new_v1, expected_v1, "new_v1 does not match expected value");

    let expected_v2 = vec![
        v2[0] * x_inv + v2[2] * x,
        v2[1] * x_inv + v2[3] * x,
    ];
    let computed_v2 = vec![Scalar::from(17u64), Scalar::from(34u64)];
    assert_eq!(new_v2, computed_v2, "new_v2 does not match the expected calculated values [17, 34]");
    assert_eq!(new_v2, expected_v2, "new_v2 does not match expected value");

    // Now verify the next pedersen commitment from the proof equals to the expected pedersen commitment
    let expected_pedersen_commitment = compute_pedersen_commitment(&new_v1, &new_v2, compute_dot_product(&new_v1, &new_v2), &new_generators.g, &new_generators.h, &new_generators.u);
    let verification_result = verifier::verify_rec(&proof, &BulletproofVerifierChallenge { random_challenge: challenge }, &expected_pedersen_commitment);
    assert!(verification_result, "Verification failed");
}


#[test]
fn test_prove_verify_rec_matches_mathematical_statement() {
    let mut rng = thread_rng();

    // Generate random vectors of size 4
    let v1 = vec![
        Scalar::from(2u64),
        Scalar::from(4u64),
        Scalar::from(6u64),
        Scalar::from(8u64),
    ];
    let v2 = vec![
        Scalar::from(2u64),
        Scalar::from(4u64),
        Scalar::from(8u64),
        Scalar::from(16u64),
    ];

    // Setup generators
    let generators = BulletproofGenerators {
        g: (0..4).map(|_| G1::rand(&mut rng)).collect(),
        h: (0..4).map(|_| G1::rand(&mut rng)).collect(),
        u: G1::rand(&mut rng),
    };

    // Prove
    let proof = prover::prove_rec(generators.clone(), v1.clone(), v2.clone());

    // Generate challenge
    let challenger = ConstantChallenger { constant: Scalar::from(2) };
    let challenge = challenger.generate_challenge(&proof);


    // Update the next round of generators, v1, v2
    let (new_generators, new_v1, new_v2) = prove_update(BulletproofVerifierChallenge { random_challenge: challenge }, generators, v1.clone(), v2.clone());

    // Now verify that the next pedersen commitment from the proof equals to the expected pedersen commitment
    let next_proof = prover::prove_rec(new_generators.clone(), new_v1.clone(), new_v2.clone());
    let verification_result = verifier::verify_rec(&proof, &BulletproofVerifierChallenge { random_challenge: challenge }, &next_proof.pedersen_commitment);
    assert!(verification_result, "Verification failed for proving the next round");
}


#[test]
fn test_prove_verify_rec_two_rounds() {
    let mut rng = thread_rng();

    // Generate random vectors of size 8
    let v1_size_8 = vec![
        Scalar::from(2u64),
        Scalar::from(4u64),
        Scalar::from(6u64),
        Scalar::from(8u64),
        Scalar::from(10u64),
        Scalar::from(12u64),
        Scalar::from(14u64),
        Scalar::from(16u64),
    ];
    let v2_size_8 = vec![
        Scalar::from(2u64),
        Scalar::from(4u64),
        Scalar::from(8u64),
        Scalar::from(16u64),
        Scalar::from(32u64),
        Scalar::from(64u64),
        Scalar::from(128u64),
        Scalar::from(256u64),
    ];

    // Setup generators
    let generators_size_8 = BulletproofGenerators {
        g: (0..8).map(|_| G1::rand(&mut rng)).collect(),
        h: (0..8).map(|_| G1::rand(&mut rng)).collect(),
        u: G1::rand(&mut rng),
    };

    // Prove
    let proof_size_8 = prover::prove_rec(generators_size_8.clone(), v1_size_8.clone(), v2_size_8.clone());

    // Generate challenge
    let challenger = ConstantChallenger { constant: Scalar::from(2) };
    let challenge = challenger.generate_challenge(&proof_size_8);

    // Update the next round of generators, v1, v2
    let (generators_size_4, v1_size_4, v2_size_4) = prove_update(BulletproofVerifierChallenge { random_challenge: challenge }, generators_size_8, v1_size_8.clone(), v2_size_8.clone());

    // Now verify that the next pedersen commitment from the proof equals to the expected pedersen commitment
    let proof_size_4 = prover::prove_rec(generators_size_4.clone(), v1_size_4.clone(), v2_size_4.clone());
    let verification_result = verifier::verify_rec(&proof_size_8, &BulletproofVerifierChallenge { random_challenge: challenge }, &proof_size_4.pedersen_commitment);
    assert!(verification_result, "Verification failed for proving the next round");

    // Update the next round of generators, v1, v2
    let (generators_size_2, v1_size_2, v2_size_2) = prove_update(BulletproofVerifierChallenge { random_challenge: challenge }, generators_size_4, v1_size_4.clone(), v2_size_4.clone());

    // Now verify that the next pedersen commitment from the proof equals to the expected pedersen commitment
    let proof_size_2 = prover::prove_rec(generators_size_2.clone(), v1_size_2.clone(), v2_size_2.clone());
    let verification_result = verifier::verify_rec(&proof_size_4, &BulletproofVerifierChallenge { random_challenge: challenge }, &proof_size_2.pedersen_commitment);

    assert!(verification_result, "Verification failed for proving the next round");
}

#[test]
fn test_prove_verify_dot_product_size_1() {
    let constant_challenge = Scalar::from(1);  // You can change this to any constant you want
    let system = setup_system(constant_challenge);
    let (v1, v2) = generate_random_vectors(1);
    let generators = setup_generators(1);

    let proof = system.prove(generators.clone(), v1.clone(), v2.clone());
    println!("Proof: {:?}", proof);
    assert!(system.verify(proof, generators));
}

#[test]
fn test_prove_verify_dot_product_size_2() {
    let constant_challenge = Scalar::from(2);  // You can change this to any constant you want
    let system = setup_system(constant_challenge);
    let (v1, v2) = generate_random_vectors(2);
    let generators = setup_generators(2);

    let proof = system.prove(generators.clone(), v1.clone(), v2.clone());
    println!("Proof: {:?}", proof);
    assert!(system.verify(proof, generators));
}

#[test]
fn test_prove_verify_dot_product_size_4() {
    let constant_challenge = Scalar::from(2);  // You can change this to any constant you want
    let system = setup_system(constant_challenge);
    let (v1, v2) = generate_random_vectors(4);
    let generators = setup_generators(4);

    let proof = system.prove(generators.clone(), v1.clone(), v2.clone());
    assert!(system.verify(proof, generators));
}

#[test]
fn test_prove_verify_dot_product_size_8() {
    let constant_challenge = Scalar::from(2);  // You can change this to any constant you want
    let system = setup_system(constant_challenge);
    let (v1, v2) = generate_random_vectors(8);
    let generators = setup_generators(8);

    let proof = system.prove(generators.clone(), v1.clone(), v2.clone());
    assert!(system.verify(proof, generators));
}

