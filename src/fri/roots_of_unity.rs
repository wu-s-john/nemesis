use ark_bls12_377::Fr; 
use ark_ff::{Field, FftField};
use ark_poly::domain::{EvaluationDomain, GeneralEvaluationDomain};

pub fn get_root_of_unity(k: u32) -> Option<Fr> {
    let two_adic_root = Fr::TWO_ADIC_ROOT_OF_UNITY;
    let exponent = 1u64 << (Fr::TWO_ADICITY as u32 - k);
    Some(two_adic_root.pow([exponent]))
}

pub fn get_evaluation_domain(size: usize) -> Option<GeneralEvaluationDomain<Fr>> {
    GeneralEvaluationDomain::<Fr>::new(size)
}
