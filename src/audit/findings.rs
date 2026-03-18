// src/audit/findings.rs — stub, completed in Task 7
use serde::{Deserialize, Serialize};
use crate::{ChainPosition, CipherSuite, KeyInfo, NamedGroup, TlsVersion, AlgorithmId};
use chrono::NaiveDate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity { Error, Warning, Note }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingKind {
    ClassicalKeyExchangeOnly { group: NamedGroup },
    HybridKeyExchangeHrrRequired { group: NamedGroup },
    DeprecatedPqcDraftCodepoint { code_point: u16 },
    WeakSymmetricCipher { suite: CipherSuite },
    ClassicalCertificate { position: ChainPosition, key: KeyInfo, deadline: u32 },
    DowngradeAccepted,
    TlsVersionInsufficient { max_version: TlsVersion },
    CertExpiresAfterDeadline { expiry: NaiveDate, deadline: u32, algorithm: AlgorithmId },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
}
