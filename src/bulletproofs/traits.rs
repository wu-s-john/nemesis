use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ec::Group;


pub trait BulletproofSystem<S: Field, G: CurveGroup<BaseField = S>> {
    type Proof;
    type Commitment;

    fn new(max_bits: usize) -> Self;

    // This should actually
    fn prove(
        &self,
        // generators: BulletproofGenerators<G>,
        v1: Vec<G>,
        v2: Vec<G>,
    ) -> (Self::Proof, Self::Commitment);

    fn verify(&self, proof: &Self::Proof, commitment: &Self::Commitment) -> bool;
}

pub struct BulletproofGenerators<G: CurveGroup> {
    pub g: Vec<G>,
    pub h: Vec<G>,
    pub u: G,
}

pub struct BulletproofProof<S: Field, G: CurveGroup<ScalarField = S>> {
    pub dot_product: S,
    pub pedersen_commitment: G, // This is the base commitment
    pub l_value: G,             // This is the left value in the proof
    pub r_value: G,             // This is the right value in the proof
}

pub struct BulletproofVerifierChallenge<S: Field> {
    pub random_challenge: S,
}

// You can show the entire two vectors if the number of elements is less than 2
pub struct BulletproofProofSmall<S: Field, G: CurveGroup<ScalarField = S>> {
    pub v1: Vec<G>,
    pub v2: Vec<G>,
    pub dot_product: S,
}

pub trait InteractiveBulletproofSystem<S: Field, G: CurveGroup<ScalarField = S>> {
    fn prove_rec(
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> BulletproofProof<S, G>;

    fn prove_update(
        challenge: BulletproofVerifierChallenge<S>,
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> (BulletproofGenerators<G>, Vec<G>, Vec<G>);

    // It's more like they verify everything in the end
    fn verifier_rec(proof: BulletproofProof<S, G>) -> Option<BulletproofVerifierChallenge<S>>;

    fn prove_small(
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> BulletproofProofSmall<S, G>;

    fn verifier_small(proof: BulletproofProofSmall<S, G>) -> bool;
}

pub struct InteractiveBulletproof<S, G>(std::marker::PhantomData<(S, G)>);

impl<S: Field, G: CurveGroup<ScalarField = S>> InteractiveBulletproofSystem<S, G>
    for InteractiveBulletproof<S, G>
{
    fn prove_rec(
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> BulletproofProof<S, G> {

        let n = v1.len();
        assert_eq!(n, v2.len(), "Input vectors must have the same length");

        let m = n / 2;

        let (a_l, a_r) = v1.split_at(m);
        let (b_l, b_r) = v2.split_at(m);
        let (g_l, g_r) = generators.g.split_at(m);
        let (h_l, h_r) = generators.h.split_at(m);

        // Compute L = [<a_L, b_R>]U + [a_L]G_R + [b_R]H_L
        let l_value = compute_commitment(a_l, b_r, g_r, h_l, &generators.u);

        // Compute R = [<a_R, b_L>]U + [a_R]G_L + [b_L]H_R
        let r_value = compute_commitment(a_r, b_l, g_l, h_r, &generators.u);

        // Compute dot product of entire v1 and v2
        let dot_product = compute_dot_product(&v1, &v2);

        let pedersen_commitment = compute_pedersen_commitment(&v1, &v2, dot_product, &generators.g, &generators.h, &generators.u);

        BulletproofProof {
            dot_product,
            pedersen_commitment,
            l_value,
            r_value,
        }
    }

    fn prove_update(
        challenge: BulletproofVerifierChallenge<S>,
        generators: BulletproofGenerators<G>,
        v1: Vec<S>,
        v2: Vec<S>,
    ) -> (BulletproofGenerators<G>, Vec<G>, Vec<G>) {
        let x = challenge.random_challenge;
        let x_inv = x.inverse().expect("Challenge should be non-zero");

        // Update v1 and v2
        let v1_new: Vec<S> = v1.iter().zip(v2.iter())
            .map(|(a_i, b_i)| *a_i * x + *b_i * x_inv)
            .collect();
        let v2_new: Vec<S> = v1.iter().zip(v2.iter())
            .map(|(a_i, b_i)| *a_i * x_inv + *b_i * x)
            .collect();

        // Update generators
        let g_new: Vec<G> = generators.g.iter().zip(generators.h.iter())
            .map(|(g_i, h_i)| g_i.mul(x_inv) + h_i.mul(x))
            .collect();
        let h_new: Vec<G> = generators.g.iter().zip(generators.h.iter())
            .map(|(g_i, h_i)| g_i.mul(x) + h_i.mul(x_inv))
            .collect();

        // Update commitment
        let u_new = generators.u.mul(x.square()) + generators.u.mul(x_inv.square());

        let new_generators = BulletproofGenerators {
            g: g_new,
            h: h_new,
            u: u_new,
        };

        (new_generators, v1_new.iter().map(|s| G::generator().mul(s)).collect(), v2_new.iter().map(|s| G::generator().mul(s)).collect())
    }

    fn verifier_rec(proof: BulletproofProof<S, G>) -> BulletproofVerifierChallenge<S> {
        // Implement the recursive verification algorithm here
        // This is a placeholder implementation
        let random_challenge = S::zero(); // Generate actual random challenge

        // Perform verification checks
        let verification_passed = true; // Replace with actual verification logic

        if verification_passed {
            Some(BulletproofVerifierChallenge { random_challenge })
        } else {
            None
        }
    }

    fn prove_small(
        generators: BulletproofGenerators<G>,
        v1: Vec<G>,
        v2: Vec<G>,
    ) -> BulletproofProofSmall<S, G> {
        todo!()
    }

    fn verifier_small(proof: BulletproofProofSmall<S, G>) -> bool {
        todo!()
    }
}

fn compute_commitment<S: Field, G: CurveGroup<ScalarField = S>>(
    a: &[S],
    b: &[S],
    g: &[G],
    h: &[G],
    u: &G,
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