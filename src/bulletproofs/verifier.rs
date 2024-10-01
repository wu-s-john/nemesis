use ark_ec::Group;
use ark_ff::Field;

pub mod verifier {
    use crate::bulletproofs::{traits::{BulletproofGenerators, BulletproofProofSmall, BulletproofRecProof}, verifier_challenger::BulletproofVerifierChallenge};

    use super::*;

    pub fn verify_rec<S: Field, G: Group<ScalarField = S>>(
        proof: &BulletproofRecProof<S, G>,
        challenge: &BulletproofVerifierChallenge<S>,
        next_commitment: &G
    ) -> bool {
        let x = challenge.random_challenge;
        let x_inv = x.inverse().expect("Challenge should be non-zero");
    
        // Compute the new commitment using the proof values and the challenge
        let computed_commitment = proof.l_value.mul(x.square())
            + proof.r_value.mul(x_inv.square())
            + proof.pedersen_commitment;
    
        // Check if the computed commitment matches the next commitment in the chain
        computed_commitment == *next_commitment
    }

    pub fn verify_small<S: Field, G: Group<ScalarField = S>>(proof: &BulletproofProofSmall<S, G>, generators: &BulletproofGenerators<G>) -> bool {
        // make sure the generators are of only size 1
        assert!(generators.g.len() == 1 && generators.h.len() == 1);

        let g_value = generators.g[0];
        let h_value = generators.h[0];

        let computed_commitment = g_value.mul(proof.value1) + h_value.mul(proof.value2) + generators.u.mul(proof.dot_product);
        

        computed_commitment == proof.pedersen_commitment
    }
}