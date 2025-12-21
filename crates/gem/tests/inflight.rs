#![forbid(unsafe_code)]

use gem::inflight::{
    GateError, InFlightManager, RetryClass, StartRequest, StartResult, REASON_CONCURRENCY_LIMIT,
    REASON_OVERLOAD, REASON_TIMEOUT,
};
use ucf_protocol::ucf;

fn make_request(
    id: &str,
    action_type: ucf::v1::ToolActionType,
    retry_allowed: bool,
    retry_class: RetryClass,
) -> StartRequest {
    StartRequest {
        request_id: id.to_string(),
        tool_id: "tool".to_string(),
        action_id: "action".to_string(),
        timeout_ms: 10,
        retry_count: 0,
        cost_class: None,
        action_type,
        retry_allowed,
        retry_class,
    }
}

#[test]
fn inflight_limit_throttles() {
    let mut manager = InFlightManager::new(1, 4);
    let first = manager.try_start(
        make_request(
            "req-1",
            ucf::v1::ToolActionType::Read,
            true,
            RetryClass::Low,
        ),
        0,
    );
    assert!(matches!(first, StartResult::Started(_)));

    let second = manager.try_start(
        make_request(
            "req-2",
            ucf::v1::ToolActionType::Read,
            true,
            RetryClass::Low,
        ),
        0,
    );
    match second {
        StartResult::Throttled(queued) => {
            assert_eq!(queued.request_id, "req-2");
            assert_eq!(manager.queue.len(), 1);
        }
        other => panic!("unexpected start result: {other:?}"),
    }
}

#[test]
fn queue_overflow_rejects() {
    let mut manager = InFlightManager::new(1, 1);
    assert!(matches!(
        manager.try_start(
            make_request(
                "req-1",
                ucf::v1::ToolActionType::Read,
                true,
                RetryClass::Low,
            ),
            0
        ),
        StartResult::Started(_)
    ));

    assert!(matches!(
        manager.try_start(
            make_request(
                "req-2",
                ucf::v1::ToolActionType::Read,
                true,
                RetryClass::Low,
            ),
            0
        ),
        StartResult::Throttled(_)
    ));

    let overloaded = manager.try_start(
        make_request(
            "req-3",
            ucf::v1::ToolActionType::Read,
            true,
            RetryClass::Low,
        ),
        0,
    );
    assert!(matches!(overloaded, StartResult::Overloaded));
}

#[test]
fn timeout_retries_and_exhausts() {
    let mut manager = InFlightManager::new(1, 2);
    assert!(matches!(
        manager.try_start(
            make_request(
                "req-1",
                ucf::v1::ToolActionType::Read,
                true,
                RetryClass::Med,
            ),
            0
        ),
        StartResult::Started(_)
    ));

    // First timeout should retry immediately.
    let result = manager.tick(20);
    assert_eq!(result.timed_out.len(), 1);
    assert!(result.timed_out[0].retried);
    assert_eq!(
        result.timed_out[0].reason_codes,
        vec![REASON_TIMEOUT.to_string()]
    );

    // Exhaust retries.
    let _ = manager.tick(40);
    let final_tick = manager.tick(60);
    assert_eq!(final_tick.timed_out.len(), 1);
    assert!(!final_tick.timed_out[0].retried);
}

#[test]
fn deterministic_ordering_for_timeouts_and_queue() {
    let mut manager = InFlightManager::new(1, 4);
    assert!(matches!(
        manager.try_start(
            make_request("b", ucf::v1::ToolActionType::Read, false, RetryClass::None,),
            0
        ),
        StartResult::Started(_)
    ));

    assert!(matches!(
        manager.try_start(
            make_request("a", ucf::v1::ToolActionType::Read, true, RetryClass::Low,),
            0
        ),
        StartResult::Throttled(_)
    ));

    assert!(matches!(
        manager.try_start(
            make_request("c", ucf::v1::ToolActionType::Read, true, RetryClass::Low,),
            0
        ),
        StartResult::Throttled(_)
    ));

    // Force timeout for the running entry; queued order should stay FIFO and timeouts are lexicographic.
    let tick = manager.tick(20);
    assert_eq!(tick.timed_out[0].entry.request_id, "b");
    let started_ids: Vec<_> = tick.started.iter().map(|e| e.request_id.as_str()).collect();
    assert_eq!(started_ids, vec!["a"]);
}

#[test]
fn structured_errors_only() {
    let budget = GateError::concurrency_limit();
    assert_eq!(
        budget.reason_codes,
        vec![REASON_CONCURRENCY_LIMIT.to_string()]
    );
    let overload = GateError::overload();
    assert_eq!(overload.reason_codes, vec![REASON_OVERLOAD.to_string()]);
    let timeout = GateError::timeout();
    assert_eq!(timeout.reason_codes, vec![REASON_TIMEOUT.to_string()]);
}
