//! **mpc module**
//!
//! This module simulates a multi-party computation protocol, where multiple participants each generate polynomials and collaborate to generate secret slices.

use crate::sharing::ShareData;
use crate::utils;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use rand::rngs::OsRng;
use crate::utils::ANOTHER_POINT;

/// Simulates the MPC protocol to generate a secret slice.
///
/// Each participant generates a polynomial with the global secret being the sum of the constant terms of each participant.
///
/// # Parameters
/// - `parties`.
/// - `parties`: Number of participants.
/// - `threshold`: Minimum number of slices required for secret recovery.
/// - `n`: Total number of slices generated.
/// - `threshold`: Minimum number of slices required for secret recovery.
/// # Return values.
///
/// Returns the set of global secrets and generated slices.
pub fn mpc_generate_key_shares(
    parties: usize,
    threshold: usize,
    n: usize,
) -> (Scalar, Vec<ShareData>) {
    let mut global_secret = Scalar::ZERO;
    let mut party_polynomials: Vec<Vec<Scalar>> = Vec::new();
    let mut rng = OsRng;
    for _ in 0..parties {
        let mut poly = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            let coeff = utils::random_scalar(&mut rng);
            poly.push(coeff);
        }
        global_secret += poly[0];
        party_polynomials.push(poly);
    }
    let shares: Vec<ShareData> = (1..=n)
        .map(|i| {
            let x = Scalar::from(i as u64);
            let mut aggregated_share = Scalar::ZERO;
            for poly in &party_polynomials {
                let mut x_pow = Scalar::ONE;
                let mut value = Scalar::ZERO;
                for &coeff in poly {
                    value += coeff * x_pow;
                    x_pow *= x;
                }
                aggregated_share += value;
            }
            let mut local_rng = OsRng;
            let aggregated_random = utils::random_scalar(&mut local_rng);
            let commitment = RISTRETTO_BASEPOINT_POINT * aggregated_share
                + (*ANOTHER_POINT)  * aggregated_random;
            let proof =
                crate::proof::generate_proof(aggregated_share, aggregated_random, i, commitment);
            ShareData {
                index: i,
                share: aggregated_share,
                commitment,
                random: aggregated_random,
                proof,
            }
        })
        .collect();
    (global_secret, shares)
}
