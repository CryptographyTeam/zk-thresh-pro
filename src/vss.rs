//! **vss module**
//!
//! Implements Verifiable Secret Sharing (VSS) for slice validity verification.
use crate::proof;
use crate::sharing::ShareData;

/// Verify the validity of all splits (including promises and proofs).
///
/// # Parameters
///
/// - `shares`: collection of slices.
///
/// # Return value
///
/// Returns `true` if all slices are valid; otherwise returns `false`.
pub fn verify_share_validity(shares: &[ShareData]) -> bool {
    for share in shares {
        if !proof::verify_proof(&share.proof, share.commitment, share.index) {
            return false;
        }
    }
    true
}
