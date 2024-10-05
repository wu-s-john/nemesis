use ark_bls12_381::{Bls12_381, Fr, G1Projective as G1, G2Projective as G2};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly::univariate::DensePolynomial;
use crate::kzg::KZGProof;
use crate::util::VerifierChallenge;

use super::prover::prover;
use super::verifier::verifier;
use super::{KZGCommitment, KZGSystem, CRS};

pub struct KZGVerifierChallenger {
    poseidon_config: PoseidonConfig<Fr>,
}

pub struct KZGSystemImpl {
    pub crs: CRS<G1>,
    pub degree: usize,
    pub g2: G2,
    pub g2_s: G2,
    pub verifier_challenge: KZGVerifierChallenger,
}

impl KZGSystem<Fr, G1, G2> for KZGSystemImpl {
    type E = Bls12_381;
    type Poly = DensePolynomial<Fr>;

    fn prove(&self, polynomial: &Self::Poly) -> KZGProof<Fr, G1> {
        // Compute the commitment
        let commitment = prover::prover_commit(&self.crs, polynomial);

        // Generate the challenge
        let challenge = self.verifier_challenge.generate_challenge(&KZGCommitment { value: commitment });

        // Compute the proof
        prover::prover_open(&self.crs, polynomial, &challenge, &commitment)
    }

    fn verify(&self, proof: KZGProof<Fr, G1>) -> bool {
        // Generate the challenge
        let challenge = proof.challenge;

        // Verify that the challenge was generated correctly
        if !self.verifier_challenge.verify_challenge_generation(&KZGCommitment { value: proof.commitment }, &challenge) {
            return false;
        }

        println!("Challenge: {:?}", challenge);
        // Verify the proof
        verifier::verify::<Bls12_381>(proof, challenge, self.g2, self.g2_s)
    }
}

impl KZGVerifierChallenger {
    pub fn new(poseidon_config: PoseidonConfig<Fr>) -> Self {
        Self { poseidon_config }
    }

    fn hash_commitment(&self, commitment: &G1) -> Fr {
        let mut sponge = PoseidonSponge::new(&self.poseidon_config);
        let affine = commitment.into_affine();
        sponge.absorb(&affine.x());
        sponge.absorb(&affine.y());
        sponge.squeeze_field_elements(1)[0]
    }
}

impl VerifierChallenge for KZGVerifierChallenger {
    type Commitment = KZGCommitment<Fr, G1>;
    type Challenge = Fr;

    fn generate_challenge(&self, commitment: &Self::Commitment) -> Self::Challenge {
        self.hash_commitment(&commitment.value)
    }

    fn verify_challenge_generation(&self, commitment: &Self::Commitment, challenge: &Self::Challenge) -> bool {
        let computed_challenge = self.hash_commitment(&commitment.value);
        computed_challenge == *challenge
    }
}