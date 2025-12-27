#![forbid(unsafe_code)]

const ACC_DOMAIN: &[u8] = b"UCF:RPP:ACC";
const ZERO_DIGEST: [u8; 32] = [0u8; 32];
const MAX_REASON_CODES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RppCheckInputs {
    pub prev_acc: [u8; 32],
    pub prev_root: [u8; 32],
    pub new_root: [u8; 32],
    pub payload_digest: [u8; 32],
    pub ruleset_digest: [u8; 32],
    pub asset_manifest_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RppCheckResult {
    pub ok: bool,
    pub reason_codes: Vec<String>,
}

impl RppCheckResult {
    pub fn ok() -> Self {
        Self {
            ok: true,
            reason_codes: Vec::new(),
        }
    }

    pub fn fail_with_codes(mut codes: Vec<String>) -> Self {
        codes.sort();
        codes.dedup();
        codes.truncate(MAX_REASON_CODES);
        Self {
            ok: false,
            reason_codes: codes,
        }
    }
}

pub fn compute_accumulator_digest(inputs: &RppCheckInputs) -> [u8; 32] {
    let asset_manifest = inputs.asset_manifest_digest.unwrap_or(ZERO_DIGEST);
    let mut hasher = blake3::Hasher::new();
    hasher.update(ACC_DOMAIN);
    hasher.update(&inputs.prev_acc);
    hasher.update(&inputs.prev_root);
    hasher.update(&inputs.new_root);
    hasher.update(&inputs.payload_digest);
    hasher.update(&inputs.ruleset_digest);
    hasher.update(&asset_manifest);
    let digest = hasher.finalize();
    *digest.as_bytes()
}

pub fn verify_accumulator(expected_acc: [u8; 32], inputs: &RppCheckInputs) -> RppCheckResult {
    let actual = compute_accumulator_digest(inputs);
    if actual == expected_acc {
        RppCheckResult::ok()
    } else {
        RppCheckResult::fail_with_codes(vec![
            "RC.RE.INTEGRITY.DEGRADED".to_string(),
            "RC.GV.RPP.VERIFY_FAIL".to_string(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_matches_expected() {
        let inputs = RppCheckInputs {
            prev_acc: [1u8; 32],
            prev_root: [2u8; 32],
            new_root: [3u8; 32],
            payload_digest: [4u8; 32],
            ruleset_digest: [5u8; 32],
            asset_manifest_digest: None,
        };
        let expected = compute_accumulator_digest(&inputs);
        let result = verify_accumulator(expected, &inputs);
        assert!(result.ok);
        assert!(result.reason_codes.is_empty());
    }

    #[test]
    fn accumulator_mismatch_returns_reason_codes() {
        let inputs = RppCheckInputs {
            prev_acc: [1u8; 32],
            prev_root: [2u8; 32],
            new_root: [3u8; 32],
            payload_digest: [4u8; 32],
            ruleset_digest: [5u8; 32],
            asset_manifest_digest: Some([6u8; 32]),
        };
        let result = verify_accumulator([0u8; 32], &inputs);
        assert!(!result.ok);
        assert_eq!(
            result.reason_codes,
            vec![
                "RC.GV.RPP.VERIFY_FAIL".to_string(),
                "RC.RE.INTEGRITY.DEGRADED".to_string()
            ]
        );
    }
}
