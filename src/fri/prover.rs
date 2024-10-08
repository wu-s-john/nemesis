// prover.rs
// Contains the prover-side functions of the FRI protocol and related structures.

use ark_ff::{FftField, Field};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use crate::fri::merkle_tree::{LeafIndex, MerkleProof, MerkleTree, MerkleTreeOperator};

// Define the structures here
#[derive(Clone, Debug)]
pub struct FRIRecCommitment<INCH: TwoToOneCRHScheme> {
    pub merkle_root: INCH::Output,
    pub degree: usize,
}

#[derive(Clone, Debug)]
pub struct VerifierQuery<F: Field> {
    pub leaf_indices: Vec<LeafIndex<F>>,
}

#[derive(Clone, Debug)]
pub struct FRIRecProof<F: Field, INCH: TwoToOneCRHScheme> {
    pub current_merkle_root: INCH::Output,
    pub next_merkle_root: INCH::Output,
    pub current_merkle_proofs: Vec<(MerkleProof<F, INCH>, MerkleProof<F, INCH>)>,
    pub next_merkle_proofs: Vec<MerkleProof<F, INCH>>,
    pub current_evaluations: Vec<(F, F)>,
    pub next_evaluations: Vec<F>,
    pub query: VerifierQuery<F>,
}

pub struct Prover<F, P>
where
    F: FftField,
    P: DenseUVPolynomial<F>,
{
    _phantom: std::marker::PhantomData<(F, P)>,
}

impl<F, P> Prover<F, P>
where
    F: FftField,
    P: DenseUVPolynomial<F>,
{
    /// Creates an evaluation domain for the given degree.
    pub fn create_domain(degree: usize) -> GeneralEvaluationDomain<F> {
        let domain_size = (degree + 1).next_power_of_two();
        GeneralEvaluationDomain::<F>::new(domain_size)
            .expect("Failed to create evaluation domain")
    }

    /// Commits to a polynomial using the provided Merkle tree operator.
    pub fn commit_rec<LCH, INCH, MT>(
        polynomial: &P,
        root_of_unity: F,
        tree_operator: &MT,
    ) -> (MerkleTree<F, INCH>, FRIRecCommitment<INCH>)
    where
        LCH: CRHScheme<Input = [F], Output = INCH::Output>,
        INCH: TwoToOneCRHScheme,
        MT: MerkleTreeOperator<F, INCH>,
    {
        let degree = polynomial.degree();
        let domain = Self::create_domain(degree);

        // Evaluate the polynomial over the domain using FFT
        let evaluations = domain.fft(&polynomial.coeffs());

        // Collect the domain elements (points) and their corresponding evaluations
        let points: Vec<(LeafIndex<F>, F)> = domain
            .elements()
            .enumerate()
            .map(|(i, point)| {
                (
                    LeafIndex { index: i, point },
                    evaluations[i],
                )
            })
            .collect();

        // Create the Merkle tree from the evaluations
        let merkle_tree = tree_operator.create_tree(points, root_of_unity, degree);

        let commitment = FRIRecCommitment {
            merkle_root: merkle_tree.root.hash(),
            degree,
        };

        (merkle_tree, commitment)
    }

    /// Proves the evaluation of the polynomial at a given point.
    pub fn prove_evaluation<LCH, INCH, MT>(
        polynomial: &P,
        merkle_tree: &MerkleTree<F, INCH>,
        point: LeafIndex<F>,
        tree_operator: &MT,
    ) -> (F, MerkleProof<F, INCH>)
    where
        LCH: CRHScheme<Input = [F], Output = INCH::Output>,
        INCH: TwoToOneCRHScheme,
        MT: MerkleTreeOperator<F, INCH>,
    {
        let evaluation = polynomial.evaluate(&point.point);
        let proof = tree_operator.create_proof(merkle_tree, &point);
        (evaluation, proof)
    }

    /// Opens the recursive proof for the FRI protocol.
    pub fn open_rec<LCH, INCH, MT>(
        current_polynomial: &P,
        current_merkle_tree: &MerkleTree<F, INCH>,
        next_polynomial: &P,
        next_merkle_tree: &MerkleTree<F, INCH>,
        coset_shift: F,
        queries: &[LeafIndex<F>],
        tree_operator: &MT,
    ) -> FRIRecProof<F, INCH>
    where
        LCH: CRHScheme<Input = [F], Output = INCH::Output>,
        INCH: TwoToOneCRHScheme + Clone,
        MT: MerkleTreeOperator<F, INCH>,
    {
        let current_evaluations: Vec<(F, F)> = queries
            .iter()
            .map(|q| (
                current_polynomial.evaluate(&q.point),
                current_polynomial.evaluate(&(q.point * coset_shift)),
            ))
            .collect();

        let next_evaluations: Vec<F> = queries
            .iter()
            .map(|q| next_polynomial.evaluate(&q.point))
            .collect();

        let current_merkle_proofs: Vec<(MerkleProof<F, INCH>, MerkleProof<F, INCH>)> = queries
            .iter()
            .map(|q| {
                let query_proof = tree_operator.create_proof(current_merkle_tree, q);
                let coset_leaf_index = LeafIndex {
                    index: q.index,
                    point: q.point * coset_shift,
                };
                let coset_proof = tree_operator.create_proof(current_merkle_tree, &coset_leaf_index);
                (query_proof, coset_proof)
            })
            .collect();

        let next_merkle_proofs: Vec<MerkleProof<F, INCH>> = queries
            .iter()
            .map(|q| tree_operator.create_proof(next_merkle_tree, q))
            .collect();

        FRIRecProof {
            current_merkle_root: current_merkle_tree.root.hash(),
            next_merkle_root: next_merkle_tree.root.hash(),
            current_merkle_proofs,
            next_merkle_proofs,
            current_evaluations,
            next_evaluations,
            query: VerifierQuery {
                leaf_indices: queries.to_vec(),
            },
        }
    }

    /// Reduces the polynomial for the next round of the FRI protocol.
    pub fn reduce<LCH, INCH, MT>(
        polynomial: &P,
        challenge: F,
        tree_operator: &MT,
    ) -> (P, MerkleTree<F, INCH>)
    where
        LCH: CRHScheme<Input = [F], Output = INCH::Output>,
        INCH: TwoToOneCRHScheme + Clone,
        INCH::Input: From<(INCH::Output, INCH::Output)>,
        MT: MerkleTreeOperator<F, INCH>,
    {
        let degree = polynomial.degree();
        let half_degree = degree / 2;

        let mut even_coeffs = Vec::with_capacity(half_degree + 1);
        let mut odd_coeffs = Vec::with_capacity(half_degree);

        for (i, coeff) in polynomial.coeffs().iter().enumerate() {
            if i % 2 == 0 {
                even_coeffs.push(*coeff);
            } else {
                odd_coeffs.push(*coeff);
            }
        }

        // Construct the reduced polynomial: f_reduced(x) = f_even(x^2) + challenge * x * f_odd(x^2)
        let even_poly = P::from_coefficients_vec(even_coeffs);
        let scaled_odd_coeffs: Vec<F> = odd_coeffs.iter().map(|coeff| *coeff * challenge).collect();
        let scaled_odd_poly = P::from_coefficients_vec(scaled_odd_coeffs);

        let reduced_poly = even_poly.add(scaled_odd_poly);

        let domain = Self::create_domain(half_degree);

        let (merkle_tree, _) = Self::commit_rec::<LCH, INCH, MT>(
            &reduced_poly,
            domain.group_gen(),
            tree_operator,
        );

        (reduced_poly, merkle_tree)
    }

    /// Proves the small degree polynomial at the end of the FRI protocol.
    pub fn prove_small(polynomial: &P) -> Vec<F> {
        polynomial.coeffs().to_vec()
    }
}
