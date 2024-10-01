use ark_ec::Group;
use ark_ff::Field;

pub mod verifier {
    use crate::bulletproofs::{BulletproofGenerators, BulletproofProofSmall, BulletproofRecProof, BulletproofVerifierChallenge};

    use super::*;

    /// Verifies a recursive Bulletproof.
    ///
    /// After the prover commits their recursive proof, L, R, and the Pedersen commitment,
    /// the verifier needs to compute the following with the challenge that they received:
    ///
    /// P' = x^2 * L_0 + x^(-2) * R_0 + P
    ///
    /// Where:
    /// - x is the challenge
    /// - L_0 is the left value in the proof
    /// - R_0 is the right value in the proof
    /// - P is the Pedersen commitment
    pub fn verify_rec<S: Field, G: Group<ScalarField = S>>(
        proof: &BulletproofRecProof<S, G>,
        challenge: &BulletproofVerifierChallenge<S>,
        next_commitment: &G
    ) -> bool {
        let x = challenge.random_challenge;
        let x_inv = x.inverse().expect("Challenge should be non-zero");
    
        // Compute P' = x^2 * L_0 + x^(-2) * R_0 + P
        let computed_commitment = proof.l_value.mul(x.square())
            + proof.r_value.mul(x_inv.square())
            + proof.pedersen_commitment;
    
        // Check if the computed commitment matches the next commitment in the chain
        computed_commitment == *next_commitment
    }

    /// Verifies a small Bulletproof for the base case of a single scalar multiplication.
    ///
    /// This function checks the validity of a BulletproofProofSmall by:
    /// 1. Ensuring the generators are of size 1.
    /// 2. Computing a Pedersen commitment using the provided values and generators.
    /// 3. Comparing the computed commitment with the one in the proof.
    ///
    /// # Arguments
    /// * `proof` - The small Bulletproof to verify.
    /// * `generators` - The Bulletproof generators used in the proof.
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise.
    pub fn verify_small<S: Field, G: Group<ScalarField = S>>(proof: &BulletproofProofSmall<S, G>, generators: &BulletproofGenerators<G>) -> bool {
        // Ensure the generators are of size 1
        assert!(generators.g.len() == 1 && generators.h.len() == 1, "Generators must be of size 1 for small proof verification");

        let g_value = generators.g[0];
        let h_value = generators.h[0];

        // Compute the Pedersen commitment
        let computed_commitment = g_value.mul(proof.value1) + h_value.mul(proof.value2) + generators.u.mul(proof.dot_product);

        // Check if the computed commitment matches the one in the proof
        computed_commitment == proof.pedersen_commitment
    }
}