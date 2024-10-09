
use ark_ff::{FftField, Field};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};

use crate::fri::merkle_tree::{MerkleTree, MerkleTreeOperator};
use crate::fri::prover::Prover;
use crate::util::VerifierChallenge;

use super::merkle_tree::LeafIndex;
use super::prover::{FRIRecCommitment, FRIRecProof};
use super::verifier::verifier::Verifier;

// Define the FRI proof structure
pub struct FRIProtocolProof<F: Field, H> {
    pub initial_commitment: H,
    pub round_commitments: Vec<H>,
    pub round_proofs: Vec<FRIRecProof<F, H>>,
    pub final_polynomial: Vec<F>,
}

// Define the FRI system implementation
#[derive(Clone)]
pub struct FRISystemImpl<F, P, MT, VC, INCH, LCH>
where
    F: Field,
    P: DenseUVPolynomial<F>,
    MT: MerkleTreeOperator<F, INCH> + Clone,
    VC: VerifierChallenge,
    INCH: TwoToOneCRHScheme,
{
    pub max_degree: usize,
    pub num_queries: usize,
    pub tree_operator: MT,
    pub verifier_challenge: VC,
    _phantom: std::marker::PhantomData<(F, P, INCH, LCH)>,
}

pub trait FRIProtocol<F: Field, P: Polynomial<F>, INCH: TwoToOneCRHScheme> {
    fn prove(&self, polynomial: &P, degree: usize) -> FRIProtocolProof<F, INCH::Output>;
    fn verify(&self, proof: &FRIProtocolProof<F, INCH::Output>) -> bool;
}

// Implement the FRIProtocol trait for FRISystemImpl
impl<F, P, LCH, INCH, MT, VC> FRIProtocol<F, P, INCH> for FRISystemImpl<F, P, MT, VC, INCH, LCH>
where
    F: FftField,
    P: DenseUVPolynomial<F>,
    LCH: CRHScheme<Input = [F], Output = INCH::Output>,
    INCH: TwoToOneCRHScheme + PartialEq<INCH::Output>,
    MT: MerkleTreeOperator<F, INCH> + Clone,
    VC: VerifierChallenge<Commitment = INCH::Output, Challenge = F>,
    INCH::Output: PartialEq, // Add this bound
{
    fn prove(&self, polynomial: &P, degree: usize) -> FRIProtocolProof<F, INCH::Output> {
        let domain = Prover::<F, P>::create_domain(degree);

        // Initial commitment
        let mut current_poly = polynomial.clone();
        let mut current_merkle_tree = Prover::commit_rec::<LCH, INCH, MT>(
            &current_poly,
            domain.group_gen(),
            &self.tree_operator,
        ).0;
        let mut initial_merkle_hash = current_merkle_tree.root.get_hash().clone();
        let mut round_commitments = Vec::new();
        let mut round_proofs = Vec::new();

        // FRI rounds
        while current_poly.degree() > self.max_degree {
            let challenge = self.verifier_challenge.generate_challenge(&current_merkle_tree.root.get_hash());
            
            let (next_poly, next_merkle_tree) = Prover::reduce::<LCH, INCH, MT>(
                &current_poly,
                challenge,
                &self.tree_operator,
            );

            let queries :Vec<F>  = (0..self.num_queries)
                .map(|_| self.verifier_challenge.generate_challenge(&next_merkle_tree.root.get_hash()))
                .collect::<Vec<_>>();

            // Choose the correct leaf indices for the queries
            let leaf_indices: Vec<LeafIndex<F>> = queries.iter().enumerate().map(|(i, x)| {
                LeafIndex {
                    index: i,
                    point: *x,
                }
            }).collect();

            let round_proof = Prover::open_rec::<LCH, INCH, MT>(
                &current_poly,
                &current_merkle_tree,
                &next_poly,
                &next_merkle_tree,
                F::one(), // coset shift
                &leaf_indices,
                &self.tree_operator,
            );

            round_commitments.push(current_merkle_tree.root.get_hash().clone());
            round_proofs.push(round_proof);
            current_poly = next_poly;
            current_merkle_tree = next_merkle_tree;
        }

        // Final small polynomial
        let final_polynomial = Prover::prove_small(&current_poly);

        FRIProtocolProof {
            initial_commitment: initial_merkle_hash,
            round_commitments,
            round_proofs,
            final_polynomial,
        }
    }
    fn verify(&self, proof: &FRIProtocolProof<F, INCH::Output>) -> bool {
        let verifier = Verifier::<F, P, LCH, INCH, MT>::create(self.tree_operator.clone());

        // Verify initial commitment
        if !verifier.verify_rec(
            &FRIRecCommitment { merkle_root: proof.initial_commitment.clone(), degree: self.max_degree },
            &proof.round_proofs[0],
            &FRIRecCommitment { merkle_root: proof.round_commitments[0].clone(), degree: self.max_degree / 2 },
            self.verifier_challenge.generate_challenge(&proof.initial_commitment),
        ) {
            return false;
        }

        // Verify intermediate rounds
        for i in 1..proof.round_proofs.len() {
            let challenge = self.verifier_challenge.generate_challenge(&proof.round_commitments[i-1]);
            if !verifier.verify_rec(
                &FRIRecCommitment { merkle_root: proof.round_commitments[i-1].clone(), degree: self.max_degree / (2_usize.pow(i as u32)) },
                &proof.round_proofs[i],
                &FRIRecCommitment { merkle_root: proof.round_commitments[i].clone(), degree: self.max_degree / (2_usize.pow((i+1) as u32)) },
                challenge,
            ) {
                return false;
            }
        }

        // Verify final small polynomial
        Verifier::<F, P, LCH, INCH, MT>::verify_small(&proof.final_polynomial, self.max_degree / (2_usize.pow(proof.round_proofs.len() as u32)))
    }
}

// Implement a constructor for FRISystemImpl
impl<F, P, MT, VC, INCH, LCH> FRISystemImpl<F, P, MT, VC, INCH, LCH>
where
    F: Field,
    P: DenseUVPolynomial<F>,
    MT: MerkleTreeOperator<F, INCH> + Clone,
    VC: VerifierChallenge<Commitment = MerkleTree<F, INCH>, Challenge = F>,
    INCH: TwoToOneCRHScheme,
{
    pub fn new(max_degree: usize, num_queries: usize, tree_operator: MT, verifier_challenge: VC) -> Self {
        Self {
            max_degree,
            num_queries,
            tree_operator,
            verifier_challenge,
            _phantom: std::marker::PhantomData,
        }
    }
}
