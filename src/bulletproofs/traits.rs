use ark_ec::Group;
use ark_ff::Field;
use super::verifier_challenger::BulletproofVerifierChallenge;


#[derive(Clone)]
pub struct BulletproofGenerators<G: Group + Clone> {
    pub g: Vec<G>,
    pub h: Vec<G>,
    pub u: G, 
}

#[derive(Clone)]
pub struct BulletproofRecProof<S: Field + Clone, G: Group<ScalarField = S> + Clone> {
    pub dot_product: S,
    pub pedersen_commitment: G, // This is the base commitment
    pub l_value: G,             // This is the left value in the proof
    pub r_value: G,             // This is the right value in the proof
}

pub trait BulletproofSystem<S: Field + Clone, G: Group<ScalarField = S> + Clone> {
    fn prove(&self, generators: BulletproofGenerators<G>, v1: Vec<S>, v2: Vec<S>) -> BulletproofProof<S, G>;
    fn verify(&self, proof: BulletproofProof<S, G>, generators: BulletproofGenerators<G>) -> bool;
}

// Bulletproof proof for the base case which is just a single scalar multiplication
pub struct BulletproofProofSmall<S: Field> {
    pub value1: S,
    pub value2: S,
    pub dot_product: S
}

pub struct BulletproofProof<S: Field, G: Group<ScalarField = S>> {
    pub rec_proofs: Vec<(BulletproofRecProof<S, G>, BulletproofVerifierChallenge<S>)>,
    pub small_proof: BulletproofProofSmall<S>,
}


