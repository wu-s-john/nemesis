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
    pub dot_product: S,
    pub pedersen_commitment: G, // This is the base commitment
    pub l_value: G,             // This is the left value in the proof
    pub r_value: G,             // This is the right value in the proof
}

pub trait BulletproofSystem<S: Field + Clone + Debug, G: Group<ScalarField = S> + Clone + Debug> {
    fn prove(&self, generators: BulletproofGenerators<G>, v1: Vec<S>, v2: Vec<S>) -> BulletproofProof<S, G>;
    fn verify(&self, proof: BulletproofProof<S, G>, generators: BulletproofGenerators<G>) -> bool;
}

// Bulletproof proof for the base case which it is just a single scalar multiplication
#[derive(Debug)]
pub struct BulletproofProofSmall<S: Field + Debug, G: Group<ScalarField = S> + Debug> {
    pub value1: S,
    pub value2: S,
    pub dot_product: S,
    pub pedersen_commitment: G,
}

#[derive(Debug)]
pub struct BulletproofProof<S: Field + Debug, G: Group<ScalarField = S> + Debug> {
    pub rec_proofs: Vec<(BulletproofRecProof<S, G>, BulletproofVerifierChallenge<S>)>,
    pub small_proof: BulletproofProofSmall<S, G>,
}


