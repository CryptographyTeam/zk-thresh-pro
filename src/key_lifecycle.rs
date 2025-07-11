//! **key_lifecycle module**
//!
//! This module manages the key lifecycle, in compliance with NIST SP 800-57, including the states of key generation, activation, retirement, and destruction.

use chrono::{DateTime, Utc};
use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The possible states of a Key in its lifecycle.
#[derive(Debug)]
pub enum KeyState {
    Generated,
    Active,
    Retired,
    Destroyed,
}

/// A secret‐holding Key with full lifecycle management.
/// Only the `secret` field will be zeroed on drop;
/// all other fields are skipped.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    /// The secret part of the key (will be zeroized on Drop)
    pub secret: Scalar,

    /// Current Key Status (not secret)
    #[zeroize(skip)]
    pub state: KeyState,

    /// Key Creation Time (not secret)
    #[zeroize(skip)]
    pub creation_time: DateTime<Utc>,

    /// Key Activation Time (not secret)
    #[zeroize(skip)]
    pub activation_time: Option<DateTime<Utc>>,

    /// Key Retirement Time (not secret)
    #[zeroize(skip)]
    pub retirement_time: Option<DateTime<Utc>>,
}

impl Key {
    /// Creates a new key in the Generated state.
    pub fn new(secret: Scalar) -> Self {
        Self {
            secret,
            state: KeyState::Generated,
            creation_time: Utc::now(),
            activation_time: None,
            retirement_time: None,
        }
    }

    /// Activate the key.
    pub fn activate(&mut self) {
        self.state = KeyState::Active;
        self.activation_time = Some(Utc::now());
    }

    /// Retire the key (mark as no longer in use).
    pub fn retire(&mut self) {
        self.state = KeyState::Retired;
        self.retirement_time = Some(Utc::now());
    }

    /// Explicitly destroy the key now.
    /// This will zero out the secret immediately.
    pub fn destroy(&mut self) {
        // zeroize the secret scalar in-place
        self.secret.zeroize();
        self.state = KeyState::Destroyed;
    }
}
