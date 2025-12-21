#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};

use ucf_protocol::ucf;

pub const REASON_CONCURRENCY_LIMIT: &str = "RC.GE.BUDGET.CONCURRENCY_LIMIT";
pub const REASON_OVERLOAD: &str = "RC.GE.OVERLOAD";
pub const REASON_TIMEOUT: &str = "RC.GE.EXEC.TIMEOUT";

pub type RequestId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    None,
    Low,
    Med,
}

impl RetryClass {
    pub fn max_retries(self) -> u32 {
        match self {
            RetryClass::None => 0,
            RetryClass::Low => 1,
            RetryClass::Med => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRequest {
    pub request_id: RequestId,
    pub tool_id: String,
    pub action_id: String,
    pub timeout_ms: u64,
    pub retry_count: u32,
    pub cost_class: Option<String>,
    pub action_type: ucf::v1::ToolActionType,
    pub retry_allowed: bool,
    pub retry_class: RetryClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedRequest {
    pub request_id: RequestId,
    pub tool_id: String,
    pub action_id: String,
    pub timeout_ms: u64,
    pub retry_count: u32,
    pub cost_class: Option<String>,
    pub action_type: ucf::v1::ToolActionType,
    pub retry_allowed: bool,
    pub retry_class: RetryClass,
}

impl From<StartRequest> for QueuedRequest {
    fn from(value: StartRequest) -> Self {
        Self {
            request_id: value.request_id,
            tool_id: value.tool_id,
            action_id: value.action_id,
            timeout_ms: value.timeout_ms,
            retry_count: value.retry_count,
            cost_class: value.cost_class,
            action_type: value.action_type,
            retry_allowed: value.retry_allowed,
            retry_class: value.retry_class,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightEntry {
    pub request_id: RequestId,
    pub started_at_ms: u64,
    pub timeout_deadline_ms: u64,
    pub retry_count: u32,
    pub tool_id: String,
    pub action_id: String,
    pub cost_class: Option<String>,
    pub action_type: ucf::v1::ToolActionType,
    pub retry_allowed: bool,
    pub retry_class: RetryClass,
    pub timeout_ms: u64,
}

impl InFlightEntry {
    fn to_queue(&self) -> QueuedRequest {
        QueuedRequest {
            request_id: self.request_id.clone(),
            tool_id: self.tool_id.clone(),
            action_id: self.action_id.clone(),
            timeout_ms: self.timeout_ms,
            retry_count: self.retry_count,
            cost_class: self.cost_class.clone(),
            action_type: self.action_type,
            retry_allowed: self.retry_allowed,
            retry_class: self.retry_class,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartResult {
    Started(InFlightEntry),
    Throttled(QueuedRequest),
    Overloaded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutEvent {
    pub entry: InFlightEntry,
    pub retried: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickResult {
    pub timed_out: Vec<TimeoutEvent>,
    pub started: Vec<InFlightEntry>,
}

#[derive(Debug, Default)]
pub struct InFlightManager {
    pub max_inflight: usize,
    pub inflight: HashMap<RequestId, InFlightEntry>,
    pub queue: VecDeque<QueuedRequest>,
    pub max_queue: usize,
}

impl InFlightManager {
    pub fn new(max_inflight: usize, max_queue: usize) -> Self {
        Self {
            max_inflight,
            inflight: HashMap::new(),
            queue: VecDeque::with_capacity(max_queue),
            max_queue,
        }
    }

    pub fn try_start(&mut self, req: StartRequest, now_ms: u64) -> StartResult {
        if self.inflight.len() < self.max_inflight {
            let entry = Self::start_entry(req, now_ms);
            self.inflight
                .insert(entry.request_id.clone(), entry.clone());
            StartResult::Started(entry)
        } else if self.queue.len() < self.max_queue {
            let queued: QueuedRequest = req.into();
            self.queue.push_back(queued.clone());
            StartResult::Throttled(queued)
        } else {
            StartResult::Overloaded
        }
    }

    pub fn complete(&mut self, request_id: &RequestId) {
        self.inflight.remove(request_id);
    }

    pub fn tick(&mut self, now_ms: u64) -> TickResult {
        let mut result = TickResult::default();
        let mut timed_out: Vec<InFlightEntry> = self
            .inflight
            .values()
            .filter(|entry| entry.timeout_deadline_ms <= now_ms)
            .cloned()
            .collect();

        timed_out.sort_by(|a, b| a.request_id.cmp(&b.request_id));

        for entry in timed_out.iter() {
            self.inflight.remove(&entry.request_id);
        }

        for entry in timed_out.into_iter() {
            let retried = self.retry(entry.clone(), now_ms);
            result.timed_out.push(TimeoutEvent {
                entry,
                retried,
                reason_codes: vec![REASON_TIMEOUT.to_string()],
            });
        }

        result.started.extend(self.start_from_queue(now_ms));
        result
    }

    fn start_entry(req: StartRequest, now_ms: u64) -> InFlightEntry {
        InFlightEntry {
            timeout_deadline_ms: now_ms + req.timeout_ms,
            started_at_ms: now_ms,
            timeout_ms: req.timeout_ms,
            request_id: req.request_id,
            retry_count: req.retry_count,
            tool_id: req.tool_id,
            action_id: req.action_id,
            cost_class: req.cost_class,
            action_type: req.action_type,
            retry_allowed: req.retry_allowed,
            retry_class: req.retry_class,
        }
    }

    fn start_from_queue(&mut self, now_ms: u64) -> Vec<InFlightEntry> {
        let mut started = Vec::new();
        while self.inflight.len() < self.max_inflight {
            if let Some(req) = self.queue.pop_front() {
                let entry = Self::start_entry(
                    StartRequest {
                        retry_count: req.retry_count,
                        request_id: req.request_id,
                        tool_id: req.tool_id,
                        action_id: req.action_id,
                        timeout_ms: req.timeout_ms,
                        cost_class: req.cost_class,
                        action_type: req.action_type,
                        retry_allowed: req.retry_allowed,
                        retry_class: req.retry_class,
                    },
                    now_ms,
                );
                self.inflight
                    .insert(entry.request_id.clone(), entry.clone());
                started.push(entry);
            } else {
                break;
            }
        }

        started
    }

    fn retry(&mut self, entry: InFlightEntry, now_ms: u64) -> bool {
        if self.should_retry(&entry) {
            let mut retry_request = entry.to_queue();
            retry_request.retry_count += 1;
            return self.enqueue_retry(retry_request, now_ms);
        }

        false
    }

    fn enqueue_retry(&mut self, req: QueuedRequest, now_ms: u64) -> bool {
        if self.inflight.len() < self.max_inflight {
            let entry = Self::start_entry(
                StartRequest {
                    request_id: req.request_id,
                    tool_id: req.tool_id,
                    action_id: req.action_id,
                    timeout_ms: req.timeout_ms,
                    retry_count: req.retry_count,
                    cost_class: req.cost_class,
                    action_type: req.action_type,
                    retry_allowed: req.retry_allowed,
                    retry_class: req.retry_class,
                },
                now_ms,
            );
            self.inflight.insert(entry.request_id.clone(), entry);
            true
        } else if self.queue.len() < self.max_queue {
            self.queue.push_front(req);
            true
        } else {
            false
        }
    }

    fn should_retry(&self, entry: &InFlightEntry) -> bool {
        if !entry.retry_allowed {
            return false;
        }

        match entry.action_type {
            ucf::v1::ToolActionType::Read | ucf::v1::ToolActionType::Transform => {}
            _ => return false,
        }

        entry.retry_count < entry.retry_class.max_retries()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateErrorKind {
    Budget,
    Execution,
    Validation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateError {
    pub reason_codes: Vec<String>,
    pub kind: GateErrorKind,
}

impl GateError {
    pub fn concurrency_limit() -> Self {
        Self {
            reason_codes: vec![REASON_CONCURRENCY_LIMIT.to_string()],
            kind: GateErrorKind::Budget,
        }
    }

    pub fn overload() -> Self {
        Self {
            reason_codes: vec![REASON_OVERLOAD.to_string()],
            kind: GateErrorKind::Budget,
        }
    }

    pub fn timeout() -> Self {
        Self {
            reason_codes: vec![REASON_TIMEOUT.to_string()],
            kind: GateErrorKind::Execution,
        }
    }
}
