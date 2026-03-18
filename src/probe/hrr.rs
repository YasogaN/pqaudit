/// Fixed SHA-256("HelloRetryRequest") value from RFC 8446 §4.1.3
/// Used to detect HelloRetryRequests disguised as ServerHellos
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// State for tracking HelloRetryRequest during a TLS handshake.
pub struct HrrDetector {
    pub hrr_observed: bool,
    pub requested_group: Option<u16>,
}

impl HrrDetector {
    pub fn new() -> Self {
        Self { hrr_observed: false, requested_group: None }
    }
}

/// Checks whether a ServerHello's random bytes indicate a HelloRetryRequest.
/// Returns `true` if this is an HRR, `false` otherwise.
pub fn is_hrr(server_random: &[u8]) -> bool {
    server_random.len() == 32 && server_random == HRR_RANDOM
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hrr_random_detected() {
        assert!(is_hrr(&HRR_RANDOM));
    }

    #[test]
    fn normal_random_not_hrr() {
        let normal = [0u8; 32];
        assert!(!is_hrr(&normal));
    }

    #[test]
    fn short_bytes_not_hrr() {
        assert!(!is_hrr(&[0x01, 0x02]));
    }
}
