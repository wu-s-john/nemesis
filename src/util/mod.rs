use ark_ff::Field;

pub trait VerifierChallenge {
    type Commitment;
    type Challenge: Field;

    fn generate_challenge(&self, commitment: &Self::Commitment) -> Self::Challenge;
    fn verify_challenge_generation(&self, commitment: &Self::Commitment, challenge: &Self::Challenge) -> bool;
}