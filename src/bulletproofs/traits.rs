use ark_ec::CurveGroup;
use ark_ff::Field;

#[derive(Clone)]
pub struct BulletproofGenerators<G: CurveGroup + Clone> {
    pub g: Vec<G>,
    pub h: Vec<G>,
    pub u: G, 
}

#[derive(Clone)]
pub struct BulletproofRecProof<S: Field + Clone, G: CurveGroup<ScalarField = S> + Clone> {
    pub dot_product: S,
    pub pedersen_commitment: G, // This is the base commitment
    pub l_value: G,             // This is the left value in the proof
    pub r_value: G,             // This is the right value in the proof
}

#[derive(Clone)]
pub struct BulletproofVerifierChallenge<S: Field + Clone> {
    pub random_challenge: S,
}

pub trait VerifierChallenger<S: Field + Clone, G: CurveGroup<ScalarField = S> + Clone> {
    fn generate_challenge(&self, proof: &BulletproofRecProof<S, G>) -> S;
}

pub struct DefaultVerifierChallenger;

impl<S: Field + Clone, G: CurveGroup<ScalarField = S> + Clone> VerifierChallenger<S, G> for DefaultVerifierChallenger {
    fn generate_challenge(&self, proof: &BulletproofRecProof<S, G>) -> S {
        // This is a placeholder implementation.
        // In a real-world scenario, you would use a cryptographic hash function
        // to generate the challenge based on the proof components.
        // For now, we'll just return a dummy value.
        S::from(1u64)
    }
}


// You can show the entire two vectors if the number of elements is less than 2
pub struct BulletproofProofSmall<S: Field> {
    pub value1: S,
    pub value2: S,
    pub dot_product: S
}

pub struct BulletproofProof<S: Field, G: CurveGroup<ScalarField = S>> {
    pub rec_proofs: Vec<(BulletproofRecProof<S, G>, BulletproofVerifierChallenge<S>)>,
    pub small_proof: BulletproofProofSmall<S>,
}




mod prover {
    use super::*;

    fn prove_rec<S: Field, G: CurveGroup<ScalarField = S>>(
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> BulletproofRecProof<S, G> {
        let n = v1.len();
        assert_eq!(n, v2.len(), "Input vectors must have the same length");

        let m = n / 2;

        let (a_l, a_r) = v1.split_at(m);
        let (b_l, b_r) = v2.split_at(m);
        let (g_l, g_r) = generators.g.split_at(m);
        let (h_l, h_r) = generators.h.split_at(m);

        // Compute L = [<a_L, b_R>]U + [a_L]G_R + [b_R]H_L
        let l_value = compute_intermediate_commitment(a_l, b_r, &generators.u, g_r, h_l);

        // Compute R = [<a_R, b_L>]U + [a_R]G_L + [b_L]H_R
        let r_value = compute_intermediate_commitment(a_r, b_l, &generators.u, g_l, h_r);

        let dot_product = compute_dot_product(&v1, &v2);

        let pedersen_commitment = compute_pedersen_commitment(&v1, &v2, dot_product, &generators.g, &generators.h, &generators.u);

        BulletproofRecProof {
            dot_product,
            pedersen_commitment,
            l_value,
            r_value,
        }
    }

    fn prove_small<S: Field, G: CurveGroup<ScalarField = S>>(
        x1: S,
        x2: S,
    ) -> BulletproofProofSmall<S> {
        BulletproofProofSmall {
            value1: x1,
            value2: x2,
            dot_product: x1 * x2,
        }
    }

    pub fn prove<S: Field, G: CurveGroup<ScalarField = S>>(
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> BulletproofProof<S, G> {
        fn prove_recursive<S: Field, G: CurveGroup<ScalarField = S>>(
            generators: BulletproofGenerators<G>,
            v1: Vec<S>,
            v2: Vec<S>,
            mut rec_proofs: Vec<(BulletproofRecProof<S, G>, BulletproofVerifierChallenge<S>)>,
        ) -> BulletproofProof<S, G> {
            if v1.len() <= 2 {
                let small_proof = if v1.len() == 2 {
                    prove_small(v1[0], v2[0])
                } else {
                    prove_small(v1[0], v2[0])
                };
                BulletproofProof {
                    rec_proofs,
                    small_proof,
                }
            } else {
                let rec_proof = prove_rec(generators.clone(), v1.clone(), v2.clone());
                let challenge = super::verifier_rec(rec_proof.clone()).expect("Verification failed");
                rec_proofs.push((rec_proof, challenge.clone()));

                let (new_generators, new_v1, new_v2) = super::prove_update(challenge, generators, v1, v2);

                prove_recursive(new_generators, new_v1, new_v2, rec_proofs)
            }
        }

        prove_recursive(generators, v1, v2, Vec::new())
    }
}

mod verifier {
    use super::*;

    pub fn verify<S: Field, G: CurveGroup<ScalarField = S>>(proof: BulletproofProof<S, G>, generators: BulletproofGenerators<G>) -> bool {
        let current_proof = proof;
        let mut current_generators = generators;

        for i in 0..(current_proof.rec_proofs.len() - 1) {
            let (rec_proof, challenge) = &current_proof.rec_proofs[i];
            let next_commitment = &current_proof.rec_proofs[i + 1].0.pedersen_commitment;
            let verification_passed = verify_rec(rec_proof, challenge, next_commitment);
            if !verification_passed {
                return false;
            }

            current_generators = update_generators(&current_generators, challenge.random_challenge);
        }

        let small_proof = &current_proof.small_proof;
        let final_commitment = &current_proof.rec_proofs.last().unwrap().0.pedersen_commitment;

        verify_small(&small_proof, &current_generators, final_commitment)
    }

    fn verify_rec<S: Field, G: CurveGroup<ScalarField = S>>(
        proof: &BulletproofRecProof<S, G>,
        challenge: &BulletproofVerifierChallenge<S>,
        next_commitment: &G
    ) -> bool {
        let x = challenge.random_challenge;
        let x_inv = x.inverse().expect("Challenge should be non-zero");
    
        // Compute the new commitment using the proof values and the challenge
        let computed_commitment = proof.l_value.mul(x.square())
            + proof.r_value.mul(x_inv.square())
            + proof.pedersen_commitment;
    
        // Check if the computed commitment matches the next commitment in the chain
        computed_commitment == *next_commitment
    }

    fn verify_small<S: Field, G: CurveGroup<ScalarField = S>>(proof: &BulletproofProofSmall<S>, generators: &BulletproofGenerators<G>, final_commitment: &G) -> bool {
        // make sure the generators are of only size 1
        assert!(generators.g.len() == 1 && generators.h.len() == 1);

        let g_value = generators.g[0];
        let h_value = generators.h[0];

        let computed_commitment = g_value.mul(proof.value1) + h_value.mul(proof.value2) + generators.u.mul(proof.dot_product);

        computed_commitment == *final_commitment
    }
}




// Compute: u * <a, b> + <a, g> + <b, h>
// where <x, y> denotes the dot product or multi-scalar multiplication
fn compute_intermediate_commitment<S: Field, G: CurveGroup<ScalarField = S>>(
    a: &[S],
    b: &[S],
    u: &G,
    g: &[G],
    h: &[G],
) -> G {
    let ab_dot = compute_dot_product(a, b);
    let ag = multi_scalar_mul(a, g);
    let bh = multi_scalar_mul(b, h);
    u.mul(&ab_dot) + ag + bh
}

fn compute_dot_product<S: Field>(a: &[S], b: &[S]) -> S {
    a.iter()
        .zip(b.iter())
        .map(|(ai, bi)| *ai * *bi)
        .sum()
}

fn multi_scalar_mul<S: Field, G: CurveGroup<ScalarField = S>>(scalars: &[S], points: &[G]) -> G {
    assert_eq!(scalars.len(), points.len(), "Scalars and points must have the same length");
    scalars.iter()
        .zip(points.iter())
        .map(|(s, p)| p.mul(*s))
        .sum()
}

fn compute_pedersen_commitment<S: Field, G: CurveGroup<ScalarField = S>>(
    v1: &[S],
    v2: &[S],
    dot_product: S,
    g: &[G],
    h: &[G],
    u: &G,
) -> G {
    multi_scalar_mul(v1, g) + multi_scalar_mul(v2, h) + u.mul(&dot_product)
}

fn update_generators<S: Field, G: CurveGroup<ScalarField = S>>(
    generators: &BulletproofGenerators<G>,
    x: S,
) -> BulletproofGenerators<G> {
    let n = generators.g.len();
    let m = n / 2;
    let x_inv = x.inverse().expect("Challenge should be non-zero");

    let g_new: Vec<G> = generators.g[..m].iter().zip(generators.g[m..].iter())
        .map(|(g_l, g_r)| g_l.mul(x_inv) + g_r.mul(x))
        .collect();
    let h_new: Vec<G> = generators.h[..m].iter().zip(generators.h[m..].iter())
        .map(|(h_l, h_r)| h_l.mul(x) + h_r.mul(x_inv))
        .collect();
    let u_new = generators.u;  // U doesn't change

    BulletproofGenerators {
        g: g_new,
        h: h_new,
        u: u_new,
    }
}

pub fn prove_update<S: Field, G: CurveGroup<ScalarField = S>>(
    challenge: BulletproofVerifierChallenge<S>,
    generators: BulletproofGenerators<G>,
    v1: Vec<S>,
    v2: Vec<S>,
) -> (BulletproofGenerators<G>, Vec<S>, Vec<S>) {
    let x = challenge.random_challenge;
    let x_inv = x.inverse().expect("Challenge should be non-zero");

    let n = v1.len();
    assert_eq!(n, v2.len(), "Input vectors must have the same length");
    let m = n / 2;

    // Update v1 and v2
    let v1_new: Vec<S> = v1[..m].iter().zip(v1[m..].iter())
        .map(|(a_l, a_r)| *a_l * x_inv + *a_r * x)
        .collect();
    let v2_new: Vec<S> = v2[..m].iter().zip(v2[m..].iter())
        .map(|(b_l, b_r)| *b_l * x + *b_r * x_inv)
        .collect();

    // Update generators
    let new_generators = update_generators(&generators, x);

    (new_generators, v1_new, v2_new)
}