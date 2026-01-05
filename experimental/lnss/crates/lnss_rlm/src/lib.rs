#![forbid(unsafe_code)]

use blake3::Hasher;
use lnss_core::{
    ControlIntentClass, FeedbackAnomalyFlags, PolicyMode, RecursionDirective,
    RecursionDirectiveKind, RlmCore, RlmInput, RlmOutput, MAX_RLM_DIRECTIVES,
};

#[derive(Debug, Clone)]
pub struct RlmConfig {
    pub max_depth: u8,
    pub max_directives: usize,
}

impl Default for RlmConfig {
    fn default() -> Self {
        Self {
            max_depth: 2,
            max_directives: MAX_RLM_DIRECTIVES,
        }
    }
}

#[derive(Debug)]
pub struct RlmController {
    pub config: RlmConfig,
}

impl Default for RlmController {
    fn default() -> Self {
        Self {
            config: RlmConfig::default(),
        }
    }
}

impl RlmCore for RlmController {
    fn step(&mut self, input: &RlmInput) -> RlmOutput {
        let mut directives = Vec::new();
        let feedback_flags = input.feedback_flags;

        if feedback_flags.any() {
            directives.push(RecursionDirective::new(
                RecursionDirectiveKind::Reflect,
                "Review anomaly signals",
            ));
        }

        let allow_followup =
            input.policy_mode != PolicyMode::Strict && input.current_depth < self.config.max_depth;
        if allow_followup
            && matches!(
                input.control_intent,
                ControlIntentClass::Explore | ControlIntentClass::Reflect
            )
        {
            directives.push(RecursionDirective::new(
                RecursionDirectiveKind::Followup,
                "FOLLOWUP: deepen reasoning",
            ));
        }

        if directives.is_empty() {
            directives.push(RecursionDirective::new(
                RecursionDirectiveKind::Hold,
                "Hold recursion",
            ));
        }

        directives.truncate(self.config.max_directives);

        let self_state_digest = digest_self_state(input, feedback_flags, &directives);
        RlmOutput {
            recursion_directives: directives,
            self_state_digest,
        }
    }
}

fn digest_self_state(
    input: &RlmInput,
    feedback_flags: FeedbackAnomalyFlags,
    directives: &[RecursionDirective],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"RLM:SELF");
    hasher.update(&input.control_frame_digest);
    hasher.update(&[input.current_depth]);
    hasher.update(&[match input.policy_mode {
        PolicyMode::Open => 1,
        PolicyMode::Guarded => 2,
        PolicyMode::Strict => 3,
    }]);
    hasher.update(&[match input.control_intent {
        ControlIntentClass::Monitor => 1,
        ControlIntentClass::Explore => 2,
        ControlIntentClass::Execute => 3,
        ControlIntentClass::Reflect => 4,
    }]);
    hasher.update(&[u8::from(feedback_flags.event_queue_overflowed)]);
    hasher.update(&[u8::from(feedback_flags.events_dropped)]);
    for directive in directives {
        hasher.update(&[match directive.kind {
            RecursionDirectiveKind::Followup => 1,
            RecursionDirectiveKind::Reflect => 2,
            RecursionDirectiveKind::Hold => 3,
        }]);
        hasher.update(directive.description.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnss_core::{FeedbackAnomalyFlags, PolicyMode};

    #[test]
    fn directives_are_deterministic_and_bounded() {
        let mut controller = RlmController::default();
        let input = RlmInput {
            control_frame_digest: [9; 32],
            policy_mode: PolicyMode::Open,
            control_intent: ControlIntentClass::Explore,
            feedback_flags: FeedbackAnomalyFlags {
                event_queue_overflowed: true,
                events_dropped: false,
            },
            current_depth: 0,
        };
        let out_a = controller.step(&input);
        let out_b = controller.step(&input);
        assert_eq!(out_a.recursion_directives, out_b.recursion_directives);
        assert_eq!(out_a.self_state_digest, out_b.self_state_digest);
        assert!(out_a.recursion_directives.len() <= controller.config.max_directives);
    }
}
