use ark_ec::{pairing::Pairing, Group};

pub mod verifier {

    use crate::kzg::KZGProof;

    use super::*;

    /// Verifies a KZG proof.
    ///
    /// This function checks if the following equation holds:
    ///
    /// e(C - [y]G₁, G₂) = e(π, [s]G₂ - [α]G₂)
    ///
    /// Where:
    /// - C is the commitment
    /// - y is the claimed evaluation f(α)
    /// - G₁, G₂ are the generators of the respective groups
    /// - π is the witness (proof)
    /// - s is the secret used in the trusted setup
    /// - α is the challenge point
    /// - e(·,·) is the pairing operation
    ///
    /// This equation verifies that the polynomial committed to by C indeed evaluates to y at point α.
    pub fn verify<E>(
        proof: KZGProof<E::ScalarField, E::G1>,
        challenge: E::ScalarField,
        g2: E::G2,
        g2_s: E::G2,
    ) -> bool
    where
        E: Pairing,
        E::G1: Group<ScalarField = E::ScalarField>,
        E::G2: Group<ScalarField = E::ScalarField>,
    {
        // Convert G1 and G2 elements to E::G1 and E::G2
        let commitment = proof.commitment;
        let witness = proof.witness;
        let challenge_evaluation: E::G1 = proof.challenge_evaluation;
        
        // compute lhs = commitment - g_1^(y)
        let lhs_g1 = commitment - challenge_evaluation;
    
        // Compute g_2^(s-α)
        let g2_s_minus_alpha = g2_s - (g2 * challenge);
    
        // Compute the pairings
        let lhs = E::pairing(lhs_g1, g2);
        let rhs = E::pairing(witness, g2_s_minus_alpha);
    
        // Check if the pairings are equal
        lhs == rhs
    }
}