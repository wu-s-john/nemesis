mod prover;
mod verifier;
mod helpers;
mod verifier_challenger;
mod system;
mod test;

use ark_ec::Group;
use ark_ff::Field;
use verifier_challenger::BulletproofVerifierChallenge;
use std::fmt::Debug;


#[derive(Clone, Debug)]
pub struct BulletproofGenerators<G: Group + Clone + Debug> {
    pub g: Vec<G>,
    pub h: Vec<G>,
    pub u: G, 
}

#[derive(Clone, Debug)]
pub struct BulletproofRecProof<S: Field + Clone + Debug, G: Group<ScalarField = S> + Clone + Debug> {
    /// The dot product of the two input vectors
    pub dot_product: S,
    /// The Pedersen commitment: P = <a, G> + <b, H> + <a, b>U
    /// where a and b are the input vectors, G and H are the generator vectors, and U is the blinding factor
    pub pedersen_commitment: G,
    /// The left value in the proof: L_0 = <a_L, b_R>G + Σ(a_L,i * G_R,i) + Σ(b_R,i * H_L,i)
    /// where a_L and b_R are the left and right halves of the input vectors,
    /// G_R and H_L are the right and left halves of the generator vectors
    pub l_value: G,
    /// The right value in the proof: R_0 = <a_R, b_L>G + Σ(a_R,i * G_L,i) + Σ(b_L,i * H_R,i)
    /// where a_R and b_L are the right and left halves of the input vectors,
    /// G_L and H_R are the left and right halves of the generator vectors
    pub r_value: G,
}

pub trait BulletproofSystem<S: Field + Clone + Debug, G: Group<ScalarField = S> + Clone + Debug> {
    fn prove(&self, generators: BulletproofGenerators<G>, v1: Vec<S>, v2: Vec<S>) -> BulletproofProof<S, G>;
    fn verify(&self, proof: BulletproofProof<S, G>, generators: BulletproofGenerators<G>) -> bool;
}

/// Bulletproof proof for the base case, representing a single scalar multiplication.
/// 
/// This struct is used when the input vector is reduced to a single element through
/// the recursive process. At this point, it's computationally trivial to verify
/// the proof, so we can reveal the actual values without compromising security.
///
/// It's important to note that these values are only revealed for the final, smallest
/// step of the proof. Throughout the recursive process leading to this point, the
/// underlying values of the vectors remain hidden.
///
/// The small proof allows for direct verification by computing and comparing
/// the Pedersen commitment, providing a simple and efficient way to conclude
/// the recursive proof chain.
#[derive(Debug)]
pub struct BulletproofProofSmall<S: Field + Debug, G: Group<ScalarField = S> + Debug> {
    /// The single remaining value from the first input vector
    pub value1: S,
    /// The single remaining value from the second input vector
    pub value2: S,
    /// The dot product of value1 and value2
    pub dot_product: S,
    /// The Pedersen commitment: g*value1 + h*value2 + u*dot_product
    pub pedersen_commitment: G,
}

#[derive(Debug)]
pub struct BulletproofProof<S: Field + Debug, G: Group<ScalarField = S> + Debug> {
    pub rec_proofs: Vec<(BulletproofRecProof<S, G>, BulletproofVerifierChallenge<S>)>,
    pub small_proof: BulletproofProofSmall<S, G>,
}


