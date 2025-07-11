//! **Enterprise Error Handling Module**
//!
//! Comprehensive error types and handling for enterprise-grade applications
//! with detailed error reporting and audit trail support.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Main error type for the cryptographic library
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum CryptoError {
    #[error("Key generation failed: {reason}")]
    KeyGeneration { reason: String },

    #[error("Invalid key state transition: {from} -> {to}")]
    InvalidKeyStateTransition { from: String, to: String },

    #[error("Cryptographic operation failed: {operation}")]
    CryptographicOperation { operation: String },

    #[error("Serialization error: {details}")]
    Serialization { details: String },

    #[error("Validation failed: {field} - {reason}")]
    Validation { field: String, reason: String },

    #[error("Security violation: {details}")]
    SecurityViolation { details: String },

    #[error("Insufficient entropy: required {required}, got {actual}")]
    InsufficientEntropy { required: u32, actual: u32 },

    #[error("Timeout occurred: operation {operation} timed out after {timeout_ms}ms")]
    Timeout { operation: String, timeout_ms: u64 },

    #[error("Resource exhaustion: {resource} limit exceeded")]
    ResourceExhaustion { resource: String },

    #[error("Network error: {details}")]
    Network { details: String },

    #[error("Configuration error: {parameter} - {issue}")]
    Configuration { parameter: String, issue: String },
}

/// Security audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    KeyGenerated {
        key_id: String,
        #[serde(with = "chrono::serde::ts_seconds")]
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    KeyActivated {
        key_id: String,
        #[serde(with = "chrono::serde::ts_seconds")]
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    KeyRetired {
        key_id: String,
        #[serde(with = "chrono::serde::ts_seconds")]
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    KeyDestroyed {
        key_id: String,
        #[serde(with = "chrono::serde::ts_seconds")]
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    UnauthorizedAccess {
        attempt: String,
        #[serde(with = "chrono::serde::ts_seconds")]
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    PolicyViolation {
        policy: String,
        violation: String,
        #[serde(with = "chrono::serde::ts_seconds")]
        timestamp: chrono::DateTime<chrono::Utc>,
    },
}

/// Enterprise audit logger
pub struct AuditLogger {
    events: Vec<SecurityEvent>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn log_event(&mut self, event: SecurityEvent) {
        self.events.push(event.clone());
        // In production, this would write to secure audit log
        log::info!("Security event: {:?}", event);
    }

    pub fn get_events(&self) -> &[SecurityEvent] {
        &self.events
    }
}

/// Result type for all cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Error recovery strategies
pub enum RecoveryStrategy {
    Retry { max_attempts: u32 },
    Fallback { alternative: String },
    Abort,
}

/// Enterprise error handler with recovery capabilities
pub struct ErrorHandler {
    pub(crate) audit_logger: AuditLogger,
}

impl ErrorHandler {
    pub fn new() -> Self {
        Self {
            audit_logger: AuditLogger::new(),
        }
    }

    pub fn handle_error(&mut self, error: &CryptoError) -> RecoveryStrategy {
        match error {
            CryptoError::KeyGeneration { .. } => {
                self.audit_logger.log_event(SecurityEvent::PolicyViolation {
                    policy: "key_generation".to_string(),
                    violation: error.to_string(),
                    timestamp: chrono::Utc::now(),
                });
                RecoveryStrategy::Retry { max_attempts: 3 }
            }
            CryptoError::SecurityViolation { .. } => {
                self.audit_logger
                    .log_event(SecurityEvent::UnauthorizedAccess {
                        attempt: error.to_string(),
                        timestamp: chrono::Utc::now(),
                    });
                RecoveryStrategy::Abort
            }
            CryptoError::Timeout { .. } => RecoveryStrategy::Retry { max_attempts: 2 },
            _ => RecoveryStrategy::Fallback {
                alternative: "safe_mode".to_string(),
            },
        }
    }
}

impl Default for ErrorHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = CryptoError::KeyGeneration {
            reason: "insufficient entropy".to_string(),
        };

        assert!(error.to_string().contains("Key generation failed"));
    }

    #[test]
    fn test_audit_logging() {
        let mut logger = AuditLogger::new();
        let event = SecurityEvent::KeyGenerated {
            key_id: "test-key-001".to_string(),
            timestamp: chrono::Utc::now(),
        };

        logger.log_event(event);
        assert_eq!(logger.get_events().len(), 1);
    }

    #[test]
    fn test_error_recovery() {
        let mut handler = ErrorHandler::new();
        let error = CryptoError::Timeout {
            operation: "key_generation".to_string(),
            timeout_ms: 5000,
        };

        let strategy = handler.handle_error(&error);
        assert!(matches!(strategy, RecoveryStrategy::Retry { .. }));
    }
}
