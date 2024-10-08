use ark_ff::Field;

pub fn compute_evaluations<F: Field>(
    polynomial_coeffs: &[F],
    domain: &[F],
) -> Vec<F> {
    domain
        .iter()
        .map(|&x| {
            polynomial_coeffs
                .iter()
                .rev()
                .fold(F::zero(), |acc, &coeff| acc * x + coeff)
        })
        .collect()
}

pub fn get_coset<F: Field>(domain: &[F], shift: F) -> Vec<F> {
    domain.iter().map(|&x| x * shift).collect()
}

pub fn hash_field_elements<F: Field>(elements: &[F]) -> F {
    // Implement a simple hash function for field elements
    // In practice, use a cryptographic hash function like Poseidon
    elements.iter().fold(F::zero(), |acc, &x| acc + x)
}