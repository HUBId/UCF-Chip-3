use crate::config::{ThresholdConfig, WindowKind, WindowThresholds};
use crate::{ClassifiedSignals, IntegrityStateClass, SeverityClass};
use ucf_protocol::ucf;

fn window_kind_from_frame(frame: &ucf::v1::SignalFrame) -> Option<WindowKind> {
    frame
        .window
        .as_ref()
        .and_then(|w| match w.window_type.as_str() {
            "short" => Some(WindowKind::Short),
            "medium" => Some(WindowKind::Medium),
            "long" => Some(WindowKind::Long),
            _ => None,
        })
}

fn classify_with_thresholds(
    thresholds: &WindowThresholds,
    window: Option<WindowKind>,
    count: u64,
) -> SeverityClass {
    let window_kind = window.unwrap_or(WindowKind::Short);
    thresholds.classify(window_kind, count)
}

fn default_integrity_class(state: i32) -> IntegrityStateClass {
    match ucf::v1::IntegrityState::try_from(state) {
        Ok(ucf::v1::IntegrityState::Ok) => IntegrityStateClass::Ok,
        Ok(ucf::v1::IntegrityState::Degraded) => IntegrityStateClass::Degraded,
        Ok(ucf::v1::IntegrityState::Fail) | _ => IntegrityStateClass::Fail,
    }
}

pub fn classify_signal_frame(
    frame: &ucf::v1::SignalFrame,
    cfg: &ThresholdConfig,
) -> ClassifiedSignals {
    let window = window_kind_from_frame(frame);

    let policy_pressure_count = frame
        .policy_stats
        .as_ref()
        .map(|p| p.deny_count + p.require_approval_count + p.require_simulation_count)
        .unwrap_or(u64::MAX);
    let policy_pressure_class =
        classify_with_thresholds(&cfg.policy_pressure, window, policy_pressure_count);

    let receipt_failures_count = frame
        .receipt_stats
        .as_ref()
        .map(|r| r.receipt_invalid_count + r.receipt_missing_count)
        .unwrap_or(u64::MAX);
    let receipt_failures_class =
        classify_with_thresholds(&cfg.receipt_failures, window, receipt_failures_count);

    let dlp_count = frame
        .dlp_stats
        .as_ref()
        .map(|dlp| dlp.top_reason_codes.len() as u64);
    let dlp_severity_class =
        dlp_count.map(|count| classify_with_thresholds(&cfg.dlp_severity, window, count));

    let exec_reliability_count = frame
        .exec_stats
        .as_ref()
        .map(|e| e.failure_count + e.timeout_count + e.tool_unavailable_count);
    let exec_reliability_class = exec_reliability_count
        .map(|count| classify_with_thresholds(&cfg.exec_reliability, window, count));

    ClassifiedSignals {
        integrity_state: default_integrity_class(frame.integrity_state),
        policy_pressure_class,
        receipt_failures_class,
        dlp_severity_class,
        exec_reliability_class,
    }
}
