//! **sharing module**
//!
//! This module implements secret sharing, sharding updates and dynamic threshold adjustment.
//! Uses polynomial interpolation principle to generate slices and zero-knowledge proofs to verify the validity of slices.

use crate::utils::ANOTHER_POINT;
use crate::{lagrange_fft, proof, utils};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand::rngs::OsRng;
use rayon::prelude::*;

/// A data structure representing a secret slice and its associated data (promises, random numbers and proofs).
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ShareData {
    /// Sliced index, must be non-zero and unique.
    pub index: usize,
    /// slice value
    #[serde(with = "crate::serialization::serialize_scalar_helpers")]
    pub share: Scalar,
    /// Split promises, obtained by splitting the slice with a random number calculation.
    #[serde(with = "crate::serialization::serialize_ristretto_point_helpers")]
    pub commitment: RistrettoPoint,
    /// Random numbers for blinding.
    #[serde(with = "crate::serialization::serialize_scalar_helpers")]
    pub random: Scalar,
    /// Zero-knowledge proofs for correctness of slicing and commitment.
    pub proof: proof::Proof,
}

impl Drop for ShareData {
    /// When ShareData leaves the scope, sensitive data is cleared to reduce the risk of side-channel attacks.
    fn drop(&mut self) {
        self.share = Scalar::ZERO;
        self.random = Scalar::ZERO;
    }
}

/// Generate a secret slice.
///
/// # Parameters
///
/// - `secret`: The secret to be shared.
/// - `threshold`: Minimum number of slices needed to recover the secret.
/// - `n`: Total number of slices to generate.
/// - `threshold`: The minimum number of slices needed to recover the secret.
/// # Return value
///
/// Returns a vector containing all the sliced data.
pub fn generate_key_shares(secret: Scalar, threshold: usize, n: usize) -> Vec<ShareData> {
    let mut global_rng = OsRng;
    // Generate polynomial coefficients (except for constant terms).
    let coeffs: Vec<Scalar> = (0..(threshold - 1))
        .map(|_| utils::random_scalar(&mut global_rng))
        .collect();

    // Parallel computation of each slice with slice indexes from 1 to n guaranteed to be unique.
    (1..=n)
        .into_par_iter()
        .map(|i| {
            let mut local_rng = OsRng;
            let x = Scalar::from(i as u64);
            // 多项式 f(x)= secret + coeff_1*x + coeff_2*x^2 + ...
            let mut share = secret;
            for (j, coeff) in coeffs.iter().enumerate() {
                share += coeff * utils::pow_scalar(x, (j + 1) as u32);
            }
            let random = utils::random_scalar(&mut local_rng);
            let commitment = RISTRETTO_BASEPOINT_POINT * share + (*ANOTHER_POINT) * random;
            let proof = proof::generate_proof(share, random, i, commitment);
            ShareData {
                index: i,
                share,
                commitment,
                random,
                proof,
            }
        })
        .collect()
}

/// Updating the slice (active secret sharing).
///
/// Update the slice by adding a δ from a zero-constant random polynomial to each slice, ensuring that f(0) is unchanged.
///
/// # Parameters
///
/// - `shares`: The set of original slices.
/// - `threshold`: Threshold of the original secret shares.
///
/// # Return value
///
/// Returns the updated set of slices.
pub fn update_shares(shares: &[ShareData], threshold: usize) -> Vec<ShareData> {
    let mut rng = OsRng;
    let update_coeffs: Vec<Scalar> = (0..(threshold - 1))
        .map(|_| utils::random_scalar(&mut rng))
        .collect();

    shares
        .par_iter()
        .map(|share_data| {
            let i = share_data.index;
            let x = Scalar::from(i as u64);
            let mut update_val = Scalar::ZERO;
            for (j, coeff) in update_coeffs.iter().enumerate() {
                update_val += coeff * utils::pow_scalar(x, (j + 1) as u32);
            }
            let new_share = share_data.share + update_val;
            let mut local_rng = OsRng;
            let new_random = utils::random_scalar(&mut local_rng);
            let new_commitment =
                RISTRETTO_BASEPOINT_POINT * new_share + (*ANOTHER_POINT) * new_random;
            let new_proof = proof::generate_proof(new_share, new_random, i, new_commitment);
            ShareData {
                index: i,
                share: new_share,
                commitment: new_commitment,
                random: new_random,
                proof: new_proof,
            }
        })
        .collect()
}

/// Adjustment thresholds (distributed re-slicing).
///
/// Each original slice contributes a random polynomial value, and the new slice is the sum of the contributions, ensuring that f(0) is unchanged.
///
/// # Parameters
/// - `existing
/// - `existing_shares`: The set of original slices.
/// - `original_threshold`: The original secret sharing threshold.
/// - `new_threshold`: The new adjusted threshold.
/// - `n`: The number of new slices to generate.
///
/// # Return values
///
/// Returns a collection of new slices or an error message.
pub fn adjust_threshold(
    existing_shares: &[ShareData],
    original_threshold: usize,
    new_threshold: usize,
    n: usize,
) -> Result<Vec<ShareData>, String> {
    if existing_shares.len() < original_threshold {
        return Err(format!(
            "At least {} slices are needed for threshold adjustment",
            original_threshold
        ));
    }
    // Validate slice index: must be non-zero and unique
    let m = existing_shares.len();
    let mut indices = Vec::with_capacity(m);
    let mut index_set = std::collections::HashSet::new();
    for share in existing_shares {
        if share.index == 0 {
            return Err(format!(
                "Segmented index {} Invalid, cannot be 0",
                share.index
            ));
        }
        if !index_set.insert(share.index) {
            return Err(format!("Split Index {} Repeat", share.index));
        }
        indices.push(Scalar::from(share.index as u64));
    }
    // Calculate the Lagrange coefficient corresponding to each slice λ
    let lambda = lagrange_fft::compute_lagrange_coefficients(&indices)
        .map_err(|e| format!("计算 Lagrange 系数失败: {}", e))?;

    let mut rng = OsRng;
    let mut new_shares_vals = vec![Scalar::ZERO; n];
    let mut new_randoms = vec![Scalar::ZERO; n];
    // Each original slice contributes a random polynomial f_i(x)= share * λ_i + ∑_{k=1}^{new_threshold-1} a_{i,k} * x^k
    for (i, share) in existing_shares.iter().enumerate() {
        let const_term = share.share * lambda[i];
        let mut coeffs = vec![const_term];
        for _ in 1..new_threshold {
            coeffs.push(utils::random_scalar(&mut rng));
        }
        // For each new slice j compute f_i(j)
        for j in 1..=n {
            let x = Scalar::from(j as u64);
            let mut x_pow = Scalar::ONE;
            let mut value = Scalar::ZERO;
            for coeff in &coeffs {
                value += coeff * x_pow;
                x_pow *= x;
            }
            new_shares_vals[j - 1] += value;
            // Blinded random numbers (constant term is 0)
            let mut rand_val = Scalar::ZERO;
            let mut x_pow = x;
            for _ in 1..new_threshold {
                let a = utils::random_scalar(&mut rng);
                rand_val += a * x_pow;
                x_pow *= x;
            }
            new_randoms[j - 1] += rand_val;
        }
    }
    // Generate promises and proofs for each new slice
    let new_shares: Vec<ShareData> = (1..=n)
        .map(|j| {
            let share_val = new_shares_vals[j - 1];
            let rand_val = new_randoms[j - 1];
            let commitment = RISTRETTO_BASEPOINT_POINT * share_val + (*ANOTHER_POINT) * rand_val;
            let proof = proof::generate_proof(share_val, rand_val, j, commitment);
            ShareData {
                index: j,
                share: share_val,
                commitment,
                random: rand_val,
                proof,
            }
        })
        .collect();
    Ok(new_shares)
}
