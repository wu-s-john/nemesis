use std::marker::PhantomData;
use ark_ec::Group;
use ark_ff::Field;

use crate::bulletproofs::prover::prover;
use crate::bulletproofs::traits::BulletproofRecProof;
use crate::bulletproofs::verifier_challenger::BulletproofVerifierChallenge;
use crate::BulletproofSystem;

use super::helpers::*;
use super::traits::*;
use super::verifier::verifier;
use super::verifier_challenger::VerifierChallenger;

pub struct BulletproofSystemImpl<S, G, C>
where
    S: Field + Clone,
    G: Group<ScalarField = S> + Clone,
    C: VerifierChallenger<S, G>,
{
    pub challenger: C,
    pub _phantom: PhantomData<(S, G)>,
}

impl<S, G, C> BulletproofSystem<S, G> for BulletproofSystemImpl<S, G, C>
where
    S: Field + Clone,
    G: Group<ScalarField = S> + Clone,
    C: VerifierChallenger<S, G>,
{
    fn prove(
        &self,
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> BulletproofProof<S, G> {
        fn prove_recursive<S, G, C>(
            system: &BulletproofSystemImpl<S, G, C>,
            generators: BulletproofGenerators<G>,
            v1: Vec<S>,
            v2: Vec<S>,
            mut rec_proofs: Vec<(BulletproofRecProof<S, G>, BulletproofVerifierChallenge<S>)>,
        ) -> BulletproofProof<S, G>
        where
            S: Field + Clone,
            G: Group<ScalarField = S> + Clone,
            C: VerifierChallenger<S, G>,
        {
            if v1.len() == 0 {
                panic!("Invalid input: v1 and v2 must not be empty");
            } else if v1.len() == 1 {
                let small_proof = prover::prove_small::<S, G>(v1[0], v2[0], generators.g[0], generators.h[0], generators.u);
                BulletproofProof {
                    rec_proofs,
                    small_proof,
                }
            } else {
                let rec_proof = prover::prove_rec(generators.clone(), v1.clone(), v2.clone());
                let challenge = system.challenger.generate_challenge(&rec_proof);
                rec_proofs.push((rec_proof, BulletproofVerifierChallenge { random_challenge: challenge }));

                let (new_generators, new_v1, new_v2) = prove_update(BulletproofVerifierChallenge { random_challenge: challenge }, generators, v1, v2);

                prove_recursive(system, new_generators, new_v1, new_v2, rec_proofs)
            }
        }

        prove_recursive(self, generators, v1, v2, Vec::new())
    }

    fn verify(&self, proof: BulletproofProof<S, G>, generators: BulletproofGenerators<G>) -> bool {
        let current_proof = proof;
        let mut current_generators = generators;

        for i in 0..current_proof.rec_proofs.len() {
            let (rec_proof, challenge) = &current_proof.rec_proofs[i];
            let next_commitment = if i + 1 == current_proof.rec_proofs.len() {
                &current_proof.small_proof.pedersen_commitment
            } else {
                &current_proof.rec_proofs[i + 1].0.pedersen_commitment
            };
            let verification_passed = verifier::verify_rec(rec_proof, challenge, next_commitment);
            println!("Verification passed: {}", verification_passed);
            if !verification_passed {
                return false;
            }

            current_generators = update_generators(&current_generators, challenge.random_challenge);
        }

        let small_proof = &current_proof.small_proof;

        verifier::verify_small(&small_proof, &current_generators)
    }
}
