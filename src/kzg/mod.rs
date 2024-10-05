pub mod prover;
pub mod verifier;
pub mod system;
mod test;

use std::marker::PhantomData;

use ark_ec::{pairing::Pairing, Group};
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use crate::util::VerifierChallenge;

/// Represents a KZG (Kate-Zaverucha-Goldberg) commitment to a polynomial.
///
/// # Purpose
/// Commit to a polynomial f(x) without revealing it.
///
/// # Inputs
/// - Polynomial f(x) = ∑(i=0 to d) f_i * x^i with coefficients f_i ∈ F_q.
/// - Public parameters PP_1 = {g_1^(s^i)}(i=0 to d), where g_1 is a generator of G1.
///
/// # Output
/// - Commitment C ∈ G1
///
/// # Procedure
/// The commitment is computed as:
/// C = ∏(i=0 to d) (g_1^(s^i))^(f_i) = g_1^(f(s))
///
/// This is equivalent to evaluating f(s) in the exponent using the CRS (Common Reference String)
/// values provided in the public parameters.
pub struct KZGCommitment<F: Field, G: Group<ScalarField = F>> {
    pub value: G,
}

/// Represents a KZG (Kate-Zaverucha-Goldberg) proof, consisting of a commitment and a witness.
///
/// # Purpose
/// Prove the evaluation of a polynomial f(x) at a specific point z without revealing the entire polynomial.
///
/// # Inputs
/// - Polynomial f(x) = ∑(i=0 to d) f_i * x^i with coefficients f_i ∈ F_q.
/// - Evaluation point z ∈ F_q.
/// - Public parameters:
///   - PP_1 = {g_1^(s^i)}(i=0 to d), where g_1 is a generator of G1.
///   - PP_2 = {g_2^(s^i)}(i=0 to d), where g_2 is a generator of G2.
///
/// # Outputs
/// - Commitment C ∈ G1
/// - Witness W ∈ G1
///
/// # Procedure
/// 1. Compute the commitment:
///    C = ∏(i=0 to d) (g_1^(s^i))^(f_i) = g_1^(f(s))
///
/// 2. Compute the quotient polynomial:
///    q(x) = (f(x) - f(z)) / (x - z)
///
/// 3. Compute the witness:
///    W = ∏(i=0 to d-1) (g_1^(s^i))^(q_i) = g_1^(q(s))
///    where q_i are the coefficients of q(x).
///
/// The commitment is computed using the CRS values in PP_1, while the witness
/// is computed using a subset of these values (up to degree d-1).
#[derive(Debug, Clone)]
pub struct KZGProof<F: Field, G: Group<ScalarField = F>> {
    pub commitment: G,           // g^(f(s))
    pub challenge: F,
    pub challenge_evaluation: G, // g^(f(alpha))
    pub witness: G,              // g^(q(s))
}

pub trait KZGSystem<F: Field, G1: Group<ScalarField = F>, G2: Group<ScalarField = F>> {
    type E: Pairing;
    type Poly: Polynomial<F>;

    fn prove(&self, polynomial: &Self::Poly) -> KZGProof<F, G1>
    where
        <Self::E as Pairing>::ScalarField: From<F>,
        <Self::E as Pairing>::G1: From<G1>,
        <Self::E as Pairing>::G2: From<G2>;

    fn verify(&self, proof: KZGProof<F, G1>) -> bool
    where
        <Self::E as Pairing>::ScalarField: From<F>,
        <Self::E as Pairing>::G1: From<G1>,
        <Self::E as Pairing>::G2: From<G2>;
}

pub struct CRS<G: Group> {
    pub g1_powers: Vec<G>,
}


/// Trait for generating Common Reference String (CRS) for KZG commitments
pub trait CRSGenerator<F: Field, G: Group<ScalarField = F>> {
    /// Generates the Common Reference String (CRS) for a given degree
    ///
    /// # Arguments
    /// * `degree` - The maximum degree of polynomials that can be committed to
    ///
    /// # Returns
    /// A `CRS` struct containing the generated G1 powers
    fn generate(&self, degree: usize) -> CRS<G>;
}
