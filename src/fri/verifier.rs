use ark_poly::DenseUVPolynomial;
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use crate::fri::merkle_tree::MerkleTreeOperator;
use crate::fri::prover::{FRIRecCommitment, FRIRecProof};

pub mod verifier {
    use ark_ff::Field;
    use super::*;

    pub struct Verifier<F, P, LCH, INCH, MT>
    where
        F: Field,
        P: DenseUVPolynomial<F>,
        LCH: CRHScheme<Input = [F], Output = INCH::Output>,
        INCH: TwoToOneCRHScheme,
        MT: MerkleTreeOperator<F, INCH>,
    {
        tree_operator: MT,
        _phantom: std::marker::PhantomData<(F, P, LCH, INCH)>,
    }

    impl<F, P, LCH, INCH, MT> Verifier<F, P, LCH, INCH, MT>
    where
        F: Field,
        P: DenseUVPolynomial<F>,
        LCH: CRHScheme<Input = [F], Output = INCH::Output>,
        INCH: TwoToOneCRHScheme,
        MT: MerkleTreeOperator<F, INCH>,
    {
        pub fn new(tree_operator: MT) -> Self {
            Self {
                tree_operator,
                _phantom: std::marker::PhantomData,
            }
        }

        pub fn verify_rec(
            &self,
            current_commitment: &FRIRecCommitment<INCH>,
            round_proof: &FRIRecProof<F, INCH>,
            next_commitment: &FRIRecCommitment<INCH>,
            challenge: F,
        ) -> bool {
            // Verify Merkle proofs for both current and next polynomial evaluations
            let current_proofs_valid = round_proof.current_merkle_proofs.iter()
                .zip(&round_proof.current_evaluations)
                .all(|((proof_x, proof_wx), &(value_x, value_wx))| {
                    self.tree_operator.verify_proof(proof_x, value_x) &&
                    self.tree_operator.verify_proof(proof_wx, value_wx)
                });

            let next_proofs_valid = round_proof.next_merkle_proofs.iter()
                .zip(&round_proof.next_evaluations)
                .all(|(proof, &value)| {
                    self.tree_operator.verify_proof(proof, value)
                });

            if !current_proofs_valid || !next_proofs_valid {
                return false;
            }

            // Check the consistency equation
            let consistency_check = round_proof.current_evaluations.iter()
                .zip(&round_proof.next_evaluations)
                .zip(&round_proof.query.leaf_indices)
                .all(|(((f_x, f_wx), &f_next), leaf_index)| {
                    let y_i = leaf_index.point;
                    let s_r = F::one(); // Coset shift, typically 1 for the standard FRI
                    let lhs = F::from(2u32) * f_next;
                    let rhs = (F::one() + challenge) * f_x + (F::one() - challenge) * f_wx;
                    lhs == rhs
                });

            if !consistency_check {
                return false;
            }

            // Verify that the provided Merkle roots match the commitments
            current_commitment.merkle_root == round_proof.current_merkle_root &&
            next_commitment.merkle_root == round_proof.next_merkle_root
        }

        pub fn verify_small(
            final_polynomial: &[F],
            expected_degree: usize,
        ) -> bool {
            // Check that the length of the final_polynomial vector is at most expected_degree + 1
            if final_polynomial.len() > expected_degree + 1 {
                return false;
            }

            // Verify that the highest-degree coefficient (the last non-zero element) is indeed non-zero
            final_polynomial.iter().rev().find(|&&coeff| coeff != F::zero()).is_some()
        }
    }
}