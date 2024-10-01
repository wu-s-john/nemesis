use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ff::Field;
use ark_ff::PrimeField;
use std::fmt::Debug;

use super::BulletproofRecProof;

pub struct DefaultVerifierChallenger;

#[derive(Clone, Debug)]
pub struct BulletproofVerifierChallenge<S: Field + Clone> {
    pub random_challenge: S,
}

pub trait VerifierChallenger<S: Field + Clone, G: Group<ScalarField = S> + Clone> {
    fn generate_challenge(&self, proof: &BulletproofRecProof<S, G>) -> S;
}

impl<S, G> VerifierChallenger<S, G> for DefaultVerifierChallenger
where
    S: PrimeField + Absorb + Clone,
    G: CurveGroup<ScalarField = S, BaseField = S> + Clone,
    G::Affine: Absorb ,
{
    fn generate_challenge(&self, proof: &BulletproofRecProof<S, G>) -> S {
        // Obtain Poseidon parameters for field S
        let params = PoseidonConfig::<S>::new(
            8,  // full_rounds
            57, // partial_rounds
            5,  // alpha (exponent)
            vec![vec![S::one(); 3]; 3], // mds matrix (placeholder)
            vec![vec![S::zero(); 3]; 65], // ark (placeholder)
            2,  // rate
            1   // capacity
        );
        let mut sponge = PoseidonSponge::<S>::new(&params);
        
        let pedersen_commitment_affine = proof.pedersen_commitment.into_affine();
        sponge.absorb(&pedersen_commitment_affine.x());
        sponge.absorb(&pedersen_commitment_affine.y());

        let l_value_affine = proof.l_value.into_affine();
        sponge.absorb(&l_value_affine.x());
        sponge.absorb(&l_value_affine.y());

        let r_value_affine = proof.r_value.into_affine();
        sponge.absorb(&r_value_affine.x());
        sponge.absorb(&r_value_affine.y());

        sponge.squeeze_field_elements(1)[0]
    }
}