use ark_ec::Group;
use ark_ff::Field;

use super::{BulletproofGenerators, verifier_challenger::BulletproofVerifierChallenge};

// Compute: u * <a, b> + <a, g> + <b, h>
// where <x, y> denotes the dot product or multi-scalar multiplication
pub fn compute_intermediate_commitment<S: Field, G: Group<ScalarField = S>>(
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

pub fn compute_dot_product<S: Field>(a: &[S], b: &[S]) -> S {
    a.iter()
        .zip(b.iter())
        .map(|(ai, bi)| *ai * *bi)
        .sum()
}

pub fn compute_pedersen_commitment<S: Field, G: Group<ScalarField = S>>(
    v1: &[S],
    v2: &[S],
    dot_product: S,
    g: &[G],
    h: &[G],
    u: &G,
) -> G {
    multi_scalar_mul(v1, g) + multi_scalar_mul(v2, h) + u.mul(&dot_product)
}

fn multi_scalar_mul<S: Field, G: Group<ScalarField = S>>(scalars: &[S], points: &[G]) -> G {
    assert_eq!(scalars.len(), points.len(), "Scalars and points must have the same length");
    scalars.iter()
        .zip(points.iter())
        .map(|(s, p)| p.mul(*s))
        .sum()
}

pub fn update_generators<S: Field, G: Group<ScalarField = S>>(
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

pub fn prove_update<S: Field, G: Group<ScalarField = S>>(
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
        .map(|(a_l, a_r)| *a_l * x + *a_r * x_inv)
        .collect();
    let v2_new: Vec<S> = v2[..m].iter().zip(v2[m..].iter())
        .map(|(b_l, b_r)| *b_l * x_inv + *b_r * x)
        .collect();

    // Update generators
    let new_generators = update_generators(&generators, x);

    (new_generators, v1_new, v2_new)
}