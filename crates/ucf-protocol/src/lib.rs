//! UCF protocol core types and deterministic helpers.
#![allow(clippy::derive_partial_eq_without_eq)]

use blake3::Hasher;
use prost::Message;

pub mod ucf {
    pub mod v1 {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Digest32 {
            #[prost(bytes = "vec", tag = "1")]
            pub value: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Signature {
            #[prost(string, tag = "1")]
            pub algorithm: ::prost::alloc::string::String,
            #[prost(bytes = "vec", tag = "2")]
            pub signer: ::prost::alloc::vec::Vec<u8>,
            #[prost(bytes = "vec", tag = "3")]
            pub signature: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Ref {
            #[prost(string, tag = "1")]
            pub uri: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub label: ::prost::alloc::string::String,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct RelatedRef {
            #[prost(string, tag = "1")]
            pub id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub digest: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ReplayPlan {
            #[prost(string, tag = "1")]
            pub replay_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub replay_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "3")]
            pub trigger_reason_codes: ::core::option::Option<ReasonCodes>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MicrocircuitConfigEvidence {
            #[prost(enumeration = "MicroModule", tag = "1")]
            pub module: i32,
            #[prost(uint64, tag = "2")]
            pub version: u64,
            #[prost(message, optional, tag = "3")]
            pub config_digest: ::core::option::Option<Digest32>,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum MicroModule {
            Unspecified = 0,
            Lc = 1,
            Sn = 2,
        }
        impl MicroModule {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    MicroModule::Unspecified => "MICRO_MODULE_UNSPECIFIED",
                    MicroModule::Lc => "MICRO_MODULE_LC",
                    MicroModule::Sn => "MICRO_MODULE_SN",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "MICRO_MODULE_UNSPECIFIED" => Some(Self::Unspecified),
                    "MICRO_MODULE_LC" => Some(Self::Lc),
                    "MICRO_MODULE_SN" => Some(Self::Sn),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ReasonCodes {
            #[prost(string, repeated, tag = "1")]
            pub codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ReasonCodeCount {
            #[prost(string, tag = "1")]
            pub code: ::prost::alloc::string::String,
            #[prost(uint64, tag = "2")]
            pub count: u64,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ProposalEvidence {
            #[prost(string, tag = "1")]
            pub proposal_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub proposal_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "ProposalKind", tag = "3")]
            pub kind: i32,
            #[prost(message, optional, tag = "4")]
            pub base_evidence_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "5")]
            pub payload_digest: ::core::option::Option<Digest32>,
            #[prost(uint64, tag = "6")]
            pub created_at_ms: u64,
            #[prost(int32, tag = "7")]
            pub score: i32,
            #[prost(enumeration = "ProposalVerdict", tag = "8")]
            pub verdict: i32,
            #[prost(message, optional, tag = "9")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(message, optional, tag = "10")]
            pub context_digest: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ProposalActivationEvidence {
            #[prost(string, tag = "1")]
            pub activation_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub proposal_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "3")]
            pub approval_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "ActivationStatus", tag = "4")]
            pub status: i32,
            #[prost(uint64, tag = "5")]
            pub created_at_ms: u64,
            #[prost(message, optional, tag = "6")]
            pub active_mapping_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "7")]
            pub active_sae_pack_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "8")]
            pub active_liquid_params_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "9")]
            pub active_injection_limits: ::core::option::Option<ActivationInjectionLimits>,
            #[prost(message, optional, tag = "10")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(message, optional, tag = "11")]
            pub activation_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "12")]
            pub context_digest: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct TraceRunEvidence {
            #[prost(string, tag = "1")]
            pub trace_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub active_cfg_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "3")]
            pub shadow_cfg_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "4")]
            pub active_feedback_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "5")]
            pub shadow_feedback_digest: ::core::option::Option<Digest32>,
            #[prost(int32, tag = "6")]
            pub score_active: i32,
            #[prost(int32, tag = "7")]
            pub score_shadow: i32,
            #[prost(int32, tag = "8")]
            pub delta: i32,
            #[prost(enumeration = "TraceVerdict", tag = "9")]
            pub verdict: i32,
            #[prost(uint64, tag = "10")]
            pub created_at_ms: u64,
            #[prost(message, optional, tag = "11")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(message, optional, tag = "12")]
            pub trace_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "13")]
            pub active_context_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "14")]
            pub shadow_context_digest: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ActivationInjectionLimits {
            #[prost(uint32, tag = "1")]
            pub max_spikes_per_tick: u32,
            #[prost(uint32, tag = "2")]
            pub max_targets_per_spike: u32,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ProposalKind {
            Unspecified = 0,
            MappingUpdate = 1,
            SaePackUpdate = 2,
            LiquidParamsUpdate = 3,
            InjectionLimitsUpdate = 4,
        }
        impl ProposalKind {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ProposalKind::Unspecified => "PROPOSAL_KIND_UNSPECIFIED",
                    ProposalKind::MappingUpdate => "PROPOSAL_KIND_MAPPING_UPDATE",
                    ProposalKind::SaePackUpdate => "PROPOSAL_KIND_SAE_PACK_UPDATE",
                    ProposalKind::LiquidParamsUpdate => "PROPOSAL_KIND_LIQUID_PARAMS_UPDATE",
                    ProposalKind::InjectionLimitsUpdate => "PROPOSAL_KIND_INJECTION_LIMITS_UPDATE",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "PROPOSAL_KIND_UNSPECIFIED" => Some(Self::Unspecified),
                    "PROPOSAL_KIND_MAPPING_UPDATE" => Some(Self::MappingUpdate),
                    "PROPOSAL_KIND_SAE_PACK_UPDATE" => Some(Self::SaePackUpdate),
                    "PROPOSAL_KIND_LIQUID_PARAMS_UPDATE" => Some(Self::LiquidParamsUpdate),
                    "PROPOSAL_KIND_INJECTION_LIMITS_UPDATE" => Some(Self::InjectionLimitsUpdate),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ProposalVerdict {
            Unspecified = 0,
            Promising = 1,
            Neutral = 2,
            Risky = 3,
        }
        impl ProposalVerdict {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ProposalVerdict::Unspecified => "PROPOSAL_VERDICT_UNSPECIFIED",
                    ProposalVerdict::Promising => "PROPOSAL_VERDICT_PROMISING",
                    ProposalVerdict::Neutral => "PROPOSAL_VERDICT_NEUTRAL",
                    ProposalVerdict::Risky => "PROPOSAL_VERDICT_RISKY",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "PROPOSAL_VERDICT_UNSPECIFIED" => Some(Self::Unspecified),
                    "PROPOSAL_VERDICT_PROMISING" => Some(Self::Promising),
                    "PROPOSAL_VERDICT_NEUTRAL" => Some(Self::Neutral),
                    "PROPOSAL_VERDICT_RISKY" => Some(Self::Risky),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ActivationStatus {
            Unspecified = 0,
            Applied = 1,
            Rejected = 2,
        }
        impl ActivationStatus {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ActivationStatus::Unspecified => "ACTIVATION_STATUS_UNSPECIFIED",
                    ActivationStatus::Applied => "ACTIVATION_STATUS_APPLIED",
                    ActivationStatus::Rejected => "ACTIVATION_STATUS_REJECTED",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "ACTIVATION_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
                    "ACTIVATION_STATUS_APPLIED" => Some(Self::Applied),
                    "ACTIVATION_STATUS_REJECTED" => Some(Self::Rejected),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum TraceVerdict {
            Unspecified = 0,
            Promising = 1,
            Neutral = 2,
            Risky = 3,
        }
        impl TraceVerdict {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    TraceVerdict::Unspecified => "TRACE_VERDICT_UNSPECIFIED",
                    TraceVerdict::Promising => "TRACE_VERDICT_PROMISING",
                    TraceVerdict::Neutral => "TRACE_VERDICT_NEUTRAL",
                    TraceVerdict::Risky => "TRACE_VERDICT_RISKY",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "TRACE_VERDICT_UNSPECIFIED" => Some(Self::Unspecified),
                    "TRACE_VERDICT_PROMISING" => Some(Self::Promising),
                    "TRACE_VERDICT_NEUTRAL" => Some(Self::Neutral),
                    "TRACE_VERDICT_RISKY" => Some(Self::Risky),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum DataClass {
            Unspecified = 0,
            Public = 1,
            Confidential = 2,
            Restricted = 3,
        }
        impl DataClass {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    DataClass::Unspecified => "DATA_CLASS_UNSPECIFIED",
                    DataClass::Public => "DATA_CLASS_PUBLIC",
                    DataClass::Confidential => "DATA_CLASS_CONFIDENTIAL",
                    DataClass::Restricted => "DATA_CLASS_RESTRICTED",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "DATA_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
                    "DATA_CLASS_PUBLIC" => Some(Self::Public),
                    "DATA_CLASS_CONFIDENTIAL" => Some(Self::Confidential),
                    "DATA_CLASS_RESTRICTED" => Some(Self::Restricted),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum OutcomeStatus {
            Unspecified = 0,
            Success = 1,
            Failure = 2,
            Timeout = 3,
            Partial = 4,
            ToolUnavailable = 5,
        }
        impl OutcomeStatus {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    OutcomeStatus::Unspecified => "OUTCOME_STATUS_UNSPECIFIED",
                    OutcomeStatus::Success => "OUTCOME_STATUS_SUCCESS",
                    OutcomeStatus::Failure => "OUTCOME_STATUS_FAILURE",
                    OutcomeStatus::Timeout => "OUTCOME_STATUS_TIMEOUT",
                    OutcomeStatus::Partial => "OUTCOME_STATUS_PARTIAL",
                    OutcomeStatus::ToolUnavailable => "OUTCOME_STATUS_TOOL_UNAVAILABLE",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "OUTCOME_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
                    "OUTCOME_STATUS_SUCCESS" => Some(Self::Success),
                    "OUTCOME_STATUS_FAILURE" => Some(Self::Failure),
                    "OUTCOME_STATUS_TIMEOUT" => Some(Self::Timeout),
                    "OUTCOME_STATUS_PARTIAL" => Some(Self::Partial),
                    "OUTCOME_STATUS_TOOL_UNAVAILABLE" => Some(Self::ToolUnavailable),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum DecisionForm {
            Unspecified = 0,
            Allow = 1,
            Deny = 2,
            RequireApproval = 3,
            RequireSimulationFirst = 4,
        }
        impl DecisionForm {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    DecisionForm::Unspecified => "DECISION_FORM_UNSPECIFIED",
                    DecisionForm::Allow => "DECISION_FORM_ALLOW",
                    DecisionForm::Deny => "DECISION_FORM_DENY",
                    DecisionForm::RequireApproval => "DECISION_FORM_REQUIRE_APPROVAL",
                    DecisionForm::RequireSimulationFirst => {
                        "DECISION_FORM_REQUIRE_SIMULATION_FIRST"
                    }
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "DECISION_FORM_UNSPECIFIED" => Some(Self::Unspecified),
                    "DECISION_FORM_ALLOW" => Some(Self::Allow),
                    "DECISION_FORM_DENY" => Some(Self::Deny),
                    "DECISION_FORM_REQUIRE_APPROVAL" => Some(Self::RequireApproval),
                    "DECISION_FORM_REQUIRE_SIMULATION_FIRST" => Some(Self::RequireSimulationFirst),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum IntegrityState {
            Unspecified = 0,
            Ok = 1,
            Degraded = 2,
            Fail = 3,
        }
        impl IntegrityState {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    IntegrityState::Unspecified => "INTEGRITY_STATE_UNSPECIFIED",
                    IntegrityState::Ok => "INTEGRITY_STATE_OK",
                    IntegrityState::Degraded => "INTEGRITY_STATE_DEGRADED",
                    IntegrityState::Fail => "INTEGRITY_STATE_FAIL",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "INTEGRITY_STATE_UNSPECIFIED" => Some(Self::Unspecified),
                    "INTEGRITY_STATE_OK" => Some(Self::Ok),
                    "INTEGRITY_STATE_DEGRADED" => Some(Self::Degraded),
                    "INTEGRITY_STATE_FAIL" => Some(Self::Fail),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ConsistencyClass {
            Unspecified = 0,
            Low = 1,
            Medium = 2,
            High = 3,
        }
        impl ConsistencyClass {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ConsistencyClass::Unspecified => "CONSISTENCY_CLASS_UNSPECIFIED",
                    ConsistencyClass::Low => "CONSISTENCY_CLASS_LOW",
                    ConsistencyClass::Medium => "CONSISTENCY_CLASS_MEDIUM",
                    ConsistencyClass::High => "CONSISTENCY_CLASS_HIGH",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "CONSISTENCY_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
                    "CONSISTENCY_CLASS_LOW" => Some(Self::Low),
                    "CONSISTENCY_CLASS_MEDIUM" => Some(Self::Medium),
                    "CONSISTENCY_CLASS_HIGH" => Some(Self::High),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ConsolidationEligibility {
            Unspecified = 0,
            Allow = 1,
            Deny = 2,
        }
        impl ConsolidationEligibility {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ConsolidationEligibility::Unspecified => {
                        "CONSOLIDATION_ELIGIBILITY_UNSPECIFIED"
                    }
                    ConsolidationEligibility::Allow => "CONSOLIDATION_ELIGIBILITY_ALLOW",
                    ConsolidationEligibility::Deny => "CONSOLIDATION_ELIGIBILITY_DENY",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "CONSOLIDATION_ELIGIBILITY_UNSPECIFIED" => Some(Self::Unspecified),
                    "CONSOLIDATION_ELIGIBILITY_ALLOW" => Some(Self::Allow),
                    "CONSOLIDATION_ELIGIBILITY_DENY" => Some(Self::Deny),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum RecordType {
            Unspecified = 0,
            Policy = 1,
            Proof = 2,
            Audit = 3,
            Decision = 4,
            ActionExec = 10,
            Output = 11,
            Replay = 12,
        }
        impl RecordType {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    RecordType::Unspecified => "RECORD_TYPE_UNSPECIFIED",
                    RecordType::Policy => "RECORD_TYPE_POLICY",
                    RecordType::Proof => "RECORD_TYPE_PROOF",
                    RecordType::Audit => "RECORD_TYPE_AUDIT",
                    RecordType::Decision => "RECORD_TYPE_DECISION",
                    RecordType::ActionExec => "RECORD_TYPE_ACTION_EXEC",
                    RecordType::Output => "RECORD_TYPE_OUTPUT",
                    RecordType::Replay => "RECORD_TYPE_REPLAY",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "RECORD_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                    "RECORD_TYPE_POLICY" => Some(Self::Policy),
                    "RECORD_TYPE_PROOF" => Some(Self::Proof),
                    "RECORD_TYPE_AUDIT" => Some(Self::Audit),
                    "RECORD_TYPE_DECISION" => Some(Self::Decision),
                    "RECORD_TYPE_ACTION_EXEC" => Some(Self::ActionExec),
                    "RECORD_TYPE_OUTPUT" => Some(Self::Output),
                    "RECORD_TYPE_REPLAY" => Some(Self::Replay),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct UcfEnvelope {
            #[prost(string, tag = "1")]
            pub epoch_id: ::prost::alloc::string::String,
            #[prost(bytes = "vec", tag = "2")]
            pub nonce: ::prost::alloc::vec::Vec<u8>,
            #[prost(message, optional, tag = "3")]
            pub signature: ::core::option::Option<Signature>,
            #[prost(message, optional, tag = "4")]
            pub payload_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "MsgType", tag = "5")]
            pub msg_type: i32,
            #[prost(bytes = "vec", tag = "6")]
            pub payload: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum MsgType {
            Unspecified = 0,
            CanonicalIntent = 1,
            PolicyQuery = 2,
            PolicyDecision = 3,
            PvgsReceipt = 4,
        }
        impl MsgType {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    MsgType::Unspecified => "MSG_TYPE_UNSPECIFIED",
                    MsgType::CanonicalIntent => "MSG_TYPE_CANONICAL_INTENT",
                    MsgType::PolicyQuery => "MSG_TYPE_POLICY_QUERY",
                    MsgType::PolicyDecision => "MSG_TYPE_POLICY_DECISION",
                    MsgType::PvgsReceipt => "MSG_TYPE_PVGS_RECEIPT",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "MSG_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                    "MSG_TYPE_CANONICAL_INTENT" => Some(Self::CanonicalIntent),
                    "MSG_TYPE_POLICY_QUERY" => Some(Self::PolicyQuery),
                    "MSG_TYPE_POLICY_DECISION" => Some(Self::PolicyDecision),
                    "MSG_TYPE_PVGS_RECEIPT" => Some(Self::PvgsReceipt),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ActionSpec {
            #[prost(string, tag = "1")]
            pub verb: ::prost::alloc::string::String,
            #[prost(string, repeated, tag = "2")]
            pub resources: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ToolActionType {
            Unspecified = 0,
            Read = 1,
            Write = 2,
            Execute = 3,
            Export = 4,
            Transform = 5,
        }
        impl ToolActionType {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ToolActionType::Unspecified => "TOOL_ACTION_TYPE_UNSPECIFIED",
                    ToolActionType::Read => "TOOL_ACTION_TYPE_READ",
                    ToolActionType::Write => "TOOL_ACTION_TYPE_WRITE",
                    ToolActionType::Execute => "TOOL_ACTION_TYPE_EXECUTE",
                    ToolActionType::Export => "TOOL_ACTION_TYPE_EXPORT",
                    ToolActionType::Transform => "TOOL_ACTION_TYPE_TRANSFORM",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "TOOL_ACTION_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                    "TOOL_ACTION_TYPE_READ" => Some(Self::Read),
                    "TOOL_ACTION_TYPE_WRITE" => Some(Self::Write),
                    "TOOL_ACTION_TYPE_EXECUTE" => Some(Self::Execute),
                    "TOOL_ACTION_TYPE_EXPORT" => Some(Self::Export),
                    "TOOL_ACTION_TYPE_TRANSFORM" => Some(Self::Transform),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ToolActionProfile {
            #[prost(string, tag = "1")]
            pub tool_id: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub action_id: ::prost::alloc::string::String,
            #[prost(enumeration = "ToolActionType", tag = "3")]
            pub action_type: i32,
            #[prost(message, optional, tag = "4")]
            pub profile_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "5")]
            pub input_schema: ::core::option::Option<Ref>,
            #[prost(message, optional, tag = "6")]
            pub output_schema: ::core::option::Option<Ref>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ToolRegistryContainer {
            #[prost(string, tag = "1")]
            pub registry_id: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub registry_version: ::prost::alloc::string::String,
            #[prost(uint64, tag = "3")]
            pub created_at_ms: u64,
            #[prost(message, repeated, tag = "4")]
            pub tool_actions: ::prost::alloc::vec::Vec<ToolActionProfile>,
            #[prost(message, optional, tag = "5")]
            pub registry_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "6")]
            pub proof_receipt_ref: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "7")]
            pub attestation_sig: ::core::option::Option<Signature>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ToolOnboardingEvent {
            #[prost(string, tag = "1")]
            pub event_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub event_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "3")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ActionProgram {
            #[prost(message, repeated, tag = "1")]
            pub steps: ::prost::alloc::vec::Vec<ActionSpec>,
            #[prost(string, tag = "2")]
            pub semantics: ::prost::alloc::string::String,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct QueryParams {
            #[prost(string, tag = "1")]
            pub query: ::prost::alloc::string::String,
            #[prost(string, repeated, tag = "2")]
            pub selectors: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ExecuteParams {
            #[prost(message, optional, tag = "1")]
            pub program: ::core::option::Option<ActionProgram>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PersistParams {
            #[prost(enumeration = "RecordType", tag = "1")]
            pub record_type: i32,
            #[prost(bytes = "vec", tag = "2")]
            pub record: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ApprovalRequestParams {
            #[prost(enumeration = "DecisionForm", tag = "1")]
            pub requested_decision: i32,
            #[prost(message, optional, tag = "2")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct CanonicalIntent {
            #[prost(string, tag = "1")]
            pub intent_id: ::prost::alloc::string::String,
            #[prost(enumeration = "Channel", tag = "2")]
            pub channel: i32,
            #[prost(enumeration = "RiskLevel", tag = "3")]
            pub risk_level: i32,
            #[prost(enumeration = "DataClass", tag = "4")]
            pub data_class: i32,
            #[prost(message, optional, tag = "5")]
            pub subject: ::core::option::Option<Ref>,
            #[prost(message, optional, tag = "6")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(oneof = "canonical_intent::Params", tags = "7, 8, 9, 10")]
            pub params: ::core::option::Option<canonical_intent::Params>,
        }
        pub mod canonical_intent {
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum Params {
                #[prost(message, tag = "7")]
                Query(super::QueryParams),
                #[prost(message, tag = "8")]
                Execute(super::ExecuteParams),
                #[prost(message, tag = "9")]
                Persist(super::PersistParams),
                #[prost(message, tag = "10")]
                ApprovalRequest(super::ApprovalRequestParams),
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum Channel {
            Unspecified = 0,
            Batch = 1,
            Realtime = 2,
        }
        impl Channel {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    Channel::Unspecified => "CHANNEL_UNSPECIFIED",
                    Channel::Batch => "CHANNEL_BATCH",
                    Channel::Realtime => "CHANNEL_REALTIME",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "CHANNEL_UNSPECIFIED" => Some(Self::Unspecified),
                    "CHANNEL_BATCH" => Some(Self::Batch),
                    "CHANNEL_REALTIME" => Some(Self::Realtime),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum RiskLevel {
            Unspecified = 0,
            Low = 1,
            Medium = 2,
            High = 3,
        }
        impl RiskLevel {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    RiskLevel::Unspecified => "RISK_LEVEL_UNSPECIFIED",
                    RiskLevel::Low => "RISK_LEVEL_LOW",
                    RiskLevel::Medium => "RISK_LEVEL_MEDIUM",
                    RiskLevel::High => "RISK_LEVEL_HIGH",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "RISK_LEVEL_UNSPECIFIED" => Some(Self::Unspecified),
                    "RISK_LEVEL_LOW" => Some(Self::Low),
                    "RISK_LEVEL_MEDIUM" => Some(Self::Medium),
                    "RISK_LEVEL_HIGH" => Some(Self::High),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PolicyQuery {
            #[prost(string, tag = "1")]
            pub principal: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub action: ::core::option::Option<ActionSpec>,
            #[prost(enumeration = "Channel", tag = "3")]
            pub channel: i32,
            #[prost(enumeration = "RiskLevel", tag = "4")]
            pub risk_level: i32,
            #[prost(enumeration = "DataClass", tag = "5")]
            pub data_class: i32,
            #[prost(message, optional, tag = "6")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum PolicyEcologyBias {
            Unspecified = 0,
            Low = 1,
            Medium = 2,
            High = 3,
        }
        impl PolicyEcologyBias {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    PolicyEcologyBias::Unspecified => "POLICY_ECOLOGY_BIAS_UNSPECIFIED",
                    PolicyEcologyBias::Low => "POLICY_ECOLOGY_BIAS_LOW",
                    PolicyEcologyBias::Medium => "POLICY_ECOLOGY_BIAS_MEDIUM",
                    PolicyEcologyBias::High => "POLICY_ECOLOGY_BIAS_HIGH",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "POLICY_ECOLOGY_BIAS_UNSPECIFIED" => Some(Self::Unspecified),
                    "POLICY_ECOLOGY_BIAS_LOW" => Some(Self::Low),
                    "POLICY_ECOLOGY_BIAS_MEDIUM" => Some(Self::Medium),
                    "POLICY_ECOLOGY_BIAS_HIGH" => Some(Self::High),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PolicyEcologyVector {
            #[prost(enumeration = "PolicyEcologyBias", tag = "1")]
            pub conservatism_bias: i32,
            #[prost(enumeration = "PolicyEcologyBias", tag = "2")]
            pub novelty_penalty_bias: i32,
            #[prost(enumeration = "PolicyEcologyBias", tag = "3")]
            pub reversibility_bias: i32,
            #[prost(message, optional, tag = "4")]
            pub pev_digest: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ConstraintsDelta {
            #[prost(string, repeated, tag = "1")]
            pub constraints_added: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            #[prost(string, repeated, tag = "2")]
            pub constraints_removed: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            #[prost(bool, tag = "3")]
            pub novelty_lock: bool,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PolicyDecision {
            #[prost(enumeration = "DecisionForm", tag = "1")]
            pub decision: i32,
            #[prost(message, optional, tag = "2")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(message, optional, tag = "3")]
            pub constraints: ::core::option::Option<ConstraintsDelta>,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum OperationCategory {
            Unspecified = 0,
            OpException = 1,
            OpRecovery = 2,
            OpPersist = 3,
        }
        impl OperationCategory {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    OperationCategory::Unspecified => "OPERATION_CATEGORY_UNSPECIFIED",
                    OperationCategory::OpException => "OPERATION_CATEGORY_OP_EXCEPTION",
                    OperationCategory::OpRecovery => "OPERATION_CATEGORY_OP_RECOVERY",
                    OperationCategory::OpPersist => "OPERATION_CATEGORY_OP_PERSIST",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "OPERATION_CATEGORY_UNSPECIFIED" => Some(Self::Unspecified),
                    "OPERATION_CATEGORY_OP_EXCEPTION" => Some(Self::OpException),
                    "OPERATION_CATEGORY_OP_RECOVERY" => Some(Self::OpRecovery),
                    "OPERATION_CATEGORY_OP_PERSIST" => Some(Self::OpPersist),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ApprovalAlternativeForm {
            Unspecified = 0,
            DoNothing = 1,
            SimulateFirst = 2,
            NarrowScope = 3,
            ApplyInShadowMode = 4,
        }
        impl ApprovalAlternativeForm {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ApprovalAlternativeForm::Unspecified => "APPROVAL_ALTERNATIVE_FORM_UNSPECIFIED",
                    ApprovalAlternativeForm::DoNothing => "APPROVAL_ALTERNATIVE_FORM_DO_NOTHING",
                    ApprovalAlternativeForm::SimulateFirst => {
                        "APPROVAL_ALTERNATIVE_FORM_SIMULATE_FIRST"
                    }
                    ApprovalAlternativeForm::NarrowScope => {
                        "APPROVAL_ALTERNATIVE_FORM_NARROW_SCOPE"
                    }
                    ApprovalAlternativeForm::ApplyInShadowMode => {
                        "APPROVAL_ALTERNATIVE_FORM_APPLY_IN_SHADOW_MODE"
                    }
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "APPROVAL_ALTERNATIVE_FORM_UNSPECIFIED" => Some(Self::Unspecified),
                    "APPROVAL_ALTERNATIVE_FORM_DO_NOTHING" => Some(Self::DoNothing),
                    "APPROVAL_ALTERNATIVE_FORM_SIMULATE_FIRST" => Some(Self::SimulateFirst),
                    "APPROVAL_ALTERNATIVE_FORM_NARROW_SCOPE" => Some(Self::NarrowScope),
                    "APPROVAL_ALTERNATIVE_FORM_APPLY_IN_SHADOW_MODE" => {
                        Some(Self::ApplyInShadowMode)
                    }
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ApprovalAlternative {
            #[prost(enumeration = "ApprovalAlternativeForm", tag = "1")]
            pub form: i32,
            #[prost(string, tag = "2")]
            pub label: ::prost::alloc::string::String,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ApprovalArtifactPackage {
            #[prost(string, tag = "1")]
            pub aap_id: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub session_id: ::prost::alloc::string::String,
            #[prost(enumeration = "OperationCategory", tag = "3")]
            pub requested_operation: i32,
            #[prost(message, optional, tag = "4")]
            pub ruleset_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "5")]
            pub mapping_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "6")]
            pub sae_pack_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "7")]
            pub liquid_params_digest: ::core::option::Option<Digest32>,
            #[prost(message, repeated, tag = "8")]
            pub evidence_refs: ::prost::alloc::vec::Vec<RelatedRef>,
            #[prost(message, repeated, tag = "9")]
            pub alternatives: ::prost::alloc::vec::Vec<ApprovalAlternative>,
            #[prost(message, optional, tag = "10")]
            pub constraints: ::core::option::Option<ConstraintsDelta>,
            #[prost(message, optional, tag = "11")]
            pub aap_digest: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ApprovalDecision {
            #[prost(string, tag = "1")]
            pub decision_id: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub aap_id: ::prost::alloc::string::String,
            #[prost(enumeration = "DecisionForm", tag = "3")]
            pub decision: i32,
            #[prost(message, optional, tag = "4")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(message, optional, tag = "5")]
            pub constraints: ::core::option::Option<ConstraintsDelta>,
            #[prost(message, optional, tag = "6")]
            pub approval_decision_digest: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PvgsReceipt {
            #[prost(string, tag = "1")]
            pub receipt_epoch: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub receipt_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "3")]
            pub receipt_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "ReceiptStatus", tag = "4")]
            pub status: i32,
            #[prost(message, optional, tag = "5")]
            pub action_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "6")]
            pub decision_digest: ::core::option::Option<Digest32>,
            #[prost(string, tag = "7")]
            pub grant_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "8")]
            pub charter_version_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "9")]
            pub policy_version_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "10")]
            pub prev_record_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "11")]
            pub profile_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "12")]
            pub tool_profile_digest: ::core::option::Option<Digest32>,
            #[prost(string, repeated, tag = "13")]
            pub reject_reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            #[prost(message, optional, tag = "14")]
            pub signer: ::core::option::Option<Signature>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PvgsKeyEpoch {
            #[prost(uint64, tag = "1")]
            pub epoch_id: u64,
            #[prost(string, tag = "2")]
            pub attestation_key_id: ::prost::alloc::string::String,
            #[prost(bytes = "vec", tag = "3")]
            pub attestation_public_key: ::prost::alloc::vec::Vec<u8>,
            #[prost(message, optional, tag = "4")]
            pub announcement_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "5")]
            pub signature: ::core::option::Option<Signature>,
            #[prost(uint64, tag = "6")]
            pub timestamp_ms: u64,
            #[prost(string, optional, tag = "7")]
            pub vrf_key_id: ::core::option::Option<::prost::alloc::string::String>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ProofReceipt {
            #[prost(enumeration = "ReceiptStatus", tag = "1")]
            pub status: i32,
            #[prost(message, optional, tag = "2")]
            pub receipt_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "3")]
            pub validator: ::core::option::Option<Signature>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct CharacterBaselineVector {
            #[prost(double, repeated, tag = "1")]
            pub weights: ::prost::alloc::vec::Vec<f64>,
            #[prost(double, repeated, tag = "2")]
            pub values: ::prost::alloc::vec::Vec<f64>,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ReceiptStatus {
            Unspecified = 0,
            Accepted = 1,
            Rejected = 2,
            Pending = 3,
        }
        impl ReceiptStatus {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ReceiptStatus::Unspecified => "RECEIPT_STATUS_UNSPECIFIED",
                    ReceiptStatus::Accepted => "RECEIPT_STATUS_ACCEPTED",
                    ReceiptStatus::Rejected => "RECEIPT_STATUS_REJECTED",
                    ReceiptStatus::Pending => "RECEIPT_STATUS_PENDING",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "RECEIPT_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
                    "RECEIPT_STATUS_ACCEPTED" => Some(Self::Accepted),
                    "RECEIPT_STATUS_REJECTED" => Some(Self::Rejected),
                    "RECEIPT_STATUS_PENDING" => Some(Self::Pending),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ExecutionRequest {
            #[prost(string, tag = "1")]
            pub request_id: ::prost::alloc::string::String,
            #[prost(bytes = "vec", tag = "2")]
            pub action_digest: ::prost::alloc::vec::Vec<u8>,
            #[prost(string, tag = "3")]
            pub tool_id: ::prost::alloc::string::String,
            #[prost(string, tag = "4")]
            pub action_name: ::prost::alloc::string::String,
            #[prost(string, repeated, tag = "5")]
            pub constraints: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            #[prost(enumeration = "DataClass", tag = "6")]
            pub data_class_context: i32,
            #[prost(bytes = "vec", tag = "7")]
            pub payload: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct OutcomePacket {
            #[prost(string, tag = "1")]
            pub outcome_id: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub request_id: ::prost::alloc::string::String,
            #[prost(enumeration = "OutcomeStatus", tag = "3")]
            pub status: i32,
            #[prost(bytes = "vec", tag = "4")]
            pub payload: ::prost::alloc::vec::Vec<u8>,
            #[prost(message, optional, tag = "5")]
            pub payload_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "DataClass", tag = "6")]
            pub data_class: i32,
            #[prost(message, optional, tag = "7")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct OutputArtifact {
            #[prost(string, tag = "1")]
            pub artifact_id: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub content: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "3")]
            pub artifact_digest: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct InputPacket {
            #[prost(string, tag = "1")]
            pub request_id: ::prost::alloc::string::String,
            #[prost(bytes = "vec", tag = "2")]
            pub payload: ::prost::alloc::vec::Vec<u8>,
            #[prost(message, optional, tag = "3")]
            pub payload_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "DataClass", tag = "4")]
            pub data_class: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct WindowMetadata {
            #[prost(string, tag = "1")]
            pub window_type: ::prost::alloc::string::String,
            #[prost(uint64, tag = "2")]
            pub max_events: u64,
            #[prost(uint64, tag = "3")]
            pub event_count: u64,
            #[prost(string, tag = "4")]
            pub window_id: ::prost::alloc::string::String,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PolicyStats {
            #[prost(uint64, tag = "1")]
            pub allow_count: u64,
            #[prost(uint64, tag = "2")]
            pub deny_count: u64,
            #[prost(uint64, tag = "3")]
            pub require_approval_count: u64,
            #[prost(uint64, tag = "4")]
            pub require_simulation_count: u64,
            #[prost(message, repeated, tag = "5")]
            pub top_reason_codes: ::prost::alloc::vec::Vec<ReasonCodeCount>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ExecStats {
            #[prost(uint64, tag = "1")]
            pub success_count: u64,
            #[prost(uint64, tag = "2")]
            pub failure_count: u64,
            #[prost(uint64, tag = "3")]
            pub timeout_count: u64,
            #[prost(uint64, tag = "4")]
            pub partial_count: u64,
            #[prost(uint64, tag = "5")]
            pub tool_unavailable_count: u64,
            #[prost(message, repeated, tag = "6")]
            pub top_reason_codes: ::prost::alloc::vec::Vec<ReasonCodeCount>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct DlpStats {
            #[prost(message, repeated, tag = "1")]
            pub top_reason_codes: ::prost::alloc::vec::Vec<ReasonCodeCount>,
            #[prost(uint64, tag = "2")]
            pub block_count: u64,
            #[prost(uint64, tag = "3")]
            pub redact_count: u64,
            #[prost(uint64, tag = "4")]
            pub classify_upgrade_count: u64,
            #[prost(uint64, tag = "5")]
            pub allow_count: u64,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum DlpDecisionForm {
            Unspecified = 0,
            Allow = 1,
            Block = 2,
            Redact = 3,
            ClassifyUpgrade = 4,
        }
        impl DlpDecisionForm {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    DlpDecisionForm::Unspecified => "DLP_DECISION_FORM_UNSPECIFIED",
                    DlpDecisionForm::Allow => "DLP_DECISION_FORM_ALLOW",
                    DlpDecisionForm::Block => "DLP_DECISION_FORM_BLOCK",
                    DlpDecisionForm::Redact => "DLP_DECISION_FORM_REDACT",
                    DlpDecisionForm::ClassifyUpgrade => "DLP_DECISION_FORM_CLASSIFY_UPGRADE",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "DLP_DECISION_FORM_UNSPECIFIED" => Some(Self::Unspecified),
                    "DLP_DECISION_FORM_ALLOW" => Some(Self::Allow),
                    "DLP_DECISION_FORM_BLOCK" => Some(Self::Block),
                    "DLP_DECISION_FORM_REDACT" => Some(Self::Redact),
                    "DLP_DECISION_FORM_CLASSIFY_UPGRADE" => Some(Self::ClassifyUpgrade),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct DlpDecision {
            #[prost(enumeration = "DlpDecisionForm", tag = "1")]
            pub form: i32,
            #[prost(message, optional, tag = "2")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(message, optional, tag = "3")]
            pub dlp_decision_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "4")]
            pub artifact_ref: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct BudgetStats {
            #[prost(uint64, tag = "1")]
            pub budget_exhausted_count: u64,
            #[prost(message, repeated, tag = "2")]
            pub top_reason_codes: ::prost::alloc::vec::Vec<ReasonCodeCount>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ReceiptStats {
            #[prost(uint64, tag = "1")]
            pub receipt_missing_count: u64,
            #[prost(uint64, tag = "2")]
            pub receipt_invalid_count: u64,
            #[prost(message, repeated, tag = "3")]
            pub top_reason_codes: ::prost::alloc::vec::Vec<ReasonCodeCount>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct IntegrityStats {
            #[prost(uint64, tag = "1")]
            pub integrity_issue_count: u64,
            #[prost(message, repeated, tag = "2")]
            pub top_reason_codes: ::prost::alloc::vec::Vec<ReasonCodeCount>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct HumanStats {
            #[prost(uint64, tag = "1")]
            pub approval_denied_count: u64,
            #[prost(bool, tag = "2")]
            pub stop: bool,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct SignalFrame {
            #[prost(string, tag = "1")]
            pub frame_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub window: ::core::option::Option<WindowMetadata>,
            #[prost(enumeration = "IntegrityState", tag = "3")]
            pub integrity_state: i32,
            #[prost(message, optional, tag = "4")]
            pub policy_stats: ::core::option::Option<PolicyStats>,
            #[prost(message, optional, tag = "5")]
            pub exec_stats: ::core::option::Option<ExecStats>,
            #[prost(message, optional, tag = "6")]
            pub dlp_stats: ::core::option::Option<DlpStats>,
            #[prost(message, optional, tag = "7")]
            pub budget_stats: ::core::option::Option<BudgetStats>,
            #[prost(message, optional, tag = "8")]
            pub human_stats: ::core::option::Option<HumanStats>,
            #[prost(message, optional, tag = "9")]
            pub signal_frame_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "10")]
            pub signature: ::core::option::Option<Signature>,
            #[prost(message, optional, tag = "11")]
            pub receipt_stats: ::core::option::Option<ReceiptStats>,
            #[prost(message, optional, tag = "12")]
            pub integrity_stats: ::core::option::Option<IntegrityStats>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ConsistencyFeedback {
            #[prost(string, tag = "1")]
            pub cf_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub cf_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "ConsistencyClass", tag = "3")]
            pub consistency_class: i32,
            #[prost(string, repeated, tag = "4")]
            pub flags: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            #[prost(enumeration = "NoiseClass", tag = "5")]
            pub recommended_noise_class: i32,
            #[prost(enumeration = "ConsolidationEligibility", tag = "6")]
            pub consolidation_eligibility: i32,
            #[prost(bool, tag = "7")]
            pub replay_trigger_hint: bool,
            #[prost(message, optional, tag = "8")]
            pub pev_ref: ::core::option::Option<Digest32>,
            #[prost(message, repeated, tag = "9")]
            pub ism_refs: ::prost::alloc::vec::Vec<Digest32>,
            #[prost(message, optional, tag = "10")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(uint32, tag = "11")]
            pub deny_count_medium_window: u32,
            #[prost(enumeration = "IntegrityState", tag = "12")]
            pub integrity_state: i32,
            #[prost(uint32, tag = "13")]
            pub receipt_failures: u32,
            #[prost(message, optional, tag = "14")]
            pub ruleset_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "15")]
            pub cbv_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "16")]
            pub cbv: ::core::option::Option<CharacterBaselineVector>,
            #[prost(message, optional, tag = "17")]
            pub pev: ::core::option::Option<PolicyEcologyVector>,
            #[prost(message, optional, tag = "18")]
            pub ruleset_digest_current: ::core::option::Option<Digest32>,
            #[prost(uint32, tag = "19")]
            pub ruleset_change_count_medium_window: u32,
            #[prost(uint32, tag = "20")]
            pub receipt_invalid_count: u32,
            #[prost(uint32, tag = "21")]
            pub receipt_missing_count: u32,
            #[prost(uint32, optional, tag = "22")]
            pub dlp_block_count_medium_window: ::core::option::Option<u32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ControlFrame {
            #[prost(string, tag = "1")]
            pub frame_id: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub note: ::prost::alloc::string::String,
            #[prost(enumeration = "ControlFrameProfile", tag = "3")]
            pub active_profile: i32,
            #[prost(message, optional, tag = "4")]
            pub overlays: ::core::option::Option<ControlFrameOverlays>,
            #[prost(message, optional, tag = "5")]
            pub toolclass_mask: ::core::option::Option<ToolClassMask>,
            #[prost(bool, tag = "6")]
            pub deescalation_lock: bool,
            #[prost(message, optional, tag = "7")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
            #[prost(message, repeated, tag = "8")]
            pub evidence_refs: ::prost::alloc::vec::Vec<RelatedRef>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ControlFrameOverlays {
            #[prost(bool, tag = "1")]
            pub ovl_simulate_first: bool,
            #[prost(bool, tag = "2")]
            pub ovl_export_lock: bool,
            #[prost(bool, tag = "3")]
            pub ovl_novelty_lock: bool,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ToolClassMask {
            #[prost(bool, tag = "1")]
            pub enable_read: bool,
            #[prost(bool, tag = "2")]
            pub enable_transform: bool,
            #[prost(bool, tag = "3")]
            pub enable_export: bool,
            #[prost(bool, tag = "4")]
            pub enable_write: bool,
            #[prost(bool, tag = "5")]
            pub enable_execute: bool,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum ControlFrameProfile {
            Unspecified = 0,
            M0Baseline = 1,
            M1Restricted = 2,
        }
        impl ControlFrameProfile {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ControlFrameProfile::Unspecified => "PROFILE_UNSPECIFIED",
                    ControlFrameProfile::M0Baseline => "PROFILE_M0_BASELINE",
                    ControlFrameProfile::M1Restricted => "PROFILE_M1_RESTRICTED",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "PROFILE_UNSPECIFIED" => Some(Self::Unspecified),
                    "PROFILE_M0_BASELINE" => Some(Self::M0Baseline),
                    "PROFILE_M1_RESTRICTED" => Some(Self::M1Restricted),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum WorkspaceMode {
            Unspecified = 0,
            ExecPlan = 1,
        }
        impl WorkspaceMode {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    WorkspaceMode::Unspecified => "WORKSPACE_MODE_UNSPECIFIED",
                    WorkspaceMode::ExecPlan => "WORKSPACE_MODE_EXEC_PLAN",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "WORKSPACE_MODE_UNSPECIFIED" => Some(Self::Unspecified),
                    "WORKSPACE_MODE_EXEC_PLAN" => Some(Self::ExecPlan),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum HormoneClass {
            Unspecified = 0,
            Low = 1,
            Medium = 2,
            High = 3,
        }
        impl HormoneClass {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    HormoneClass::Unspecified => "HORMONE_CLASS_UNSPECIFIED",
                    HormoneClass::Low => "HORMONE_CLASS_LOW",
                    HormoneClass::Medium => "HORMONE_CLASS_MEDIUM",
                    HormoneClass::High => "HORMONE_CLASS_HIGH",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "HORMONE_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
                    "HORMONE_CLASS_LOW" => Some(Self::Low),
                    "HORMONE_CLASS_MEDIUM" => Some(Self::Medium),
                    "HORMONE_CLASS_HIGH" => Some(Self::High),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum NoiseClass {
            Unspecified = 0,
            Low = 1,
            Medium = 2,
            High = 3,
        }
        impl NoiseClass {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    NoiseClass::Unspecified => "NOISE_CLASS_UNSPECIFIED",
                    NoiseClass::Low => "NOISE_CLASS_LOW",
                    NoiseClass::Medium => "NOISE_CLASS_MEDIUM",
                    NoiseClass::High => "NOISE_CLASS_HIGH",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "NOISE_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
                    "NOISE_CLASS_LOW" => Some(Self::Low),
                    "NOISE_CLASS_MEDIUM" => Some(Self::Medium),
                    "NOISE_CLASS_HIGH" => Some(Self::High),
                    _ => None,
                }
            }
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum PriorityClass {
            Unspecified = 0,
            Low = 1,
            Medium = 2,
            High = 3,
        }
        impl PriorityClass {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    PriorityClass::Unspecified => "PRIORITY_CLASS_UNSPECIFIED",
                    PriorityClass::Low => "PRIORITY_CLASS_LOW",
                    PriorityClass::Medium => "PRIORITY_CLASS_MEDIUM",
                    PriorityClass::High => "PRIORITY_CLASS_HIGH",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "PRIORITY_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
                    "PRIORITY_CLASS_LOW" => Some(Self::Low),
                    "PRIORITY_CLASS_MEDIUM" => Some(Self::Medium),
                    "PRIORITY_CLASS_HIGH" => Some(Self::High),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ExperienceRange {
            #[prost(uint64, tag = "1")]
            pub start: u64,
            #[prost(uint64, tag = "2")]
            pub end: u64,
            #[prost(message, optional, tag = "3")]
            pub head_record_digest: ::core::option::Option<Digest32>,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum MicroMilestoneState {
            Unspecified = 0,
            Draft = 1,
            Sealed = 2,
            Finalized = 3,
        }
        impl MicroMilestoneState {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    MicroMilestoneState::Unspecified => "MICRO_MILESTONE_STATE_UNSPECIFIED",
                    MicroMilestoneState::Draft => "MICRO_MILESTONE_STATE_DRAFT",
                    MicroMilestoneState::Sealed => "MICRO_MILESTONE_STATE_SEALED",
                    MicroMilestoneState::Finalized => "MICRO_MILESTONE_STATE_FINALIZED",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "MICRO_MILESTONE_STATE_UNSPECIFIED" => Some(Self::Unspecified),
                    "MICRO_MILESTONE_STATE_DRAFT" => Some(Self::Draft),
                    "MICRO_MILESTONE_STATE_SEALED" => Some(Self::Sealed),
                    "MICRO_MILESTONE_STATE_FINALIZED" => Some(Self::Finalized),
                    _ => None,
                }
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MicroMilestone {
            #[prost(string, tag = "1")]
            pub micro_id: ::prost::alloc::string::String,
            #[prost(message, optional, tag = "2")]
            pub experience_range: ::core::option::Option<ExperienceRange>,
            #[prost(message, optional, tag = "3")]
            pub summary_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "HormoneClass", tag = "4")]
            pub hormone_profile: i32,
            #[prost(enumeration = "PriorityClass", tag = "5")]
            pub priority_class: i32,
            #[prost(message, optional, tag = "6")]
            pub micro_digest: ::core::option::Option<Digest32>,
            #[prost(enumeration = "MicroMilestoneState", tag = "7")]
            pub state: i32,
            #[prost(message, optional, tag = "8")]
            pub vrf_proof_ref: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "9")]
            pub proof_receipt_ref: ::core::option::Option<Digest32>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct CoreFrame {
            #[prost(string, tag = "1")]
            pub session_id: ::prost::alloc::string::String,
            #[prost(string, tag = "2")]
            pub step_id: ::prost::alloc::string::String,
            #[prost(message, repeated, tag = "3")]
            pub input_packet_refs: ::prost::alloc::vec::Vec<Digest32>,
            #[prost(message, repeated, tag = "4")]
            pub intent_refs: ::prost::alloc::vec::Vec<Digest32>,
            #[prost(message, repeated, tag = "5")]
            pub candidate_refs: ::prost::alloc::vec::Vec<Digest32>,
            #[prost(enumeration = "WorkspaceMode", tag = "6")]
            pub workspace_mode: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MetabolicFrame {
            #[prost(enumeration = "ControlFrameProfile", tag = "1")]
            pub profile_state: i32,
            #[prost(message, optional, tag = "2")]
            pub control_frame_ref: ::core::option::Option<Digest32>,
            #[prost(enumeration = "HormoneClass", repeated, tag = "3")]
            pub hormone_classes: ::prost::alloc::vec::Vec<i32>,
            #[prost(enumeration = "NoiseClass", tag = "4")]
            pub noise_class: i32,
            #[prost(enumeration = "PriorityClass", tag = "5")]
            pub priority_class: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct GovernanceFrame {
            #[prost(message, repeated, tag = "1")]
            pub policy_decision_refs: ::prost::alloc::vec::Vec<Digest32>,
            #[prost(message, repeated, tag = "2")]
            pub grant_refs: ::prost::alloc::vec::Vec<Digest32>,
            #[prost(message, repeated, tag = "3")]
            pub dlp_refs: ::prost::alloc::vec::Vec<Digest32>,
            #[prost(message, optional, tag = "4")]
            pub budget_snapshot_ref: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "5")]
            pub pvgs_receipt_ref: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "6")]
            pub reason_codes: ::core::option::Option<ReasonCodes>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ExperienceRecord {
            #[prost(enumeration = "RecordType", tag = "1")]
            pub record_type: i32,
            #[prost(message, optional, tag = "2")]
            pub core_frame: ::core::option::Option<CoreFrame>,
            #[prost(message, optional, tag = "3")]
            pub metabolic_frame: ::core::option::Option<MetabolicFrame>,
            #[prost(message, optional, tag = "4")]
            pub governance_frame: ::core::option::Option<GovernanceFrame>,
            #[prost(message, optional, tag = "5")]
            pub core_frame_ref: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "6")]
            pub metabolic_frame_ref: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "7")]
            pub governance_frame_ref: ::core::option::Option<Digest32>,
            #[prost(message, repeated, tag = "8")]
            pub related_refs: ::prost::alloc::vec::Vec<RelatedRef>,
        }
    }
}

/// Canonically encode a protobuf message using deterministic field ordering.
pub fn canonical_bytes<M: Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}

/// Compute a 32-byte digest using BLAKE3 over DOMAIN || schema_id || schema_version || bytes.
pub fn digest32(domain: &str, schema_id: &str, schema_version: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(schema_id.as_bytes());
    hasher.update(schema_version.as_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Compute a 32-byte digest using BLAKE3 over DOMAIN || message bytes.
pub fn digest_proto(domain: &str, message_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(message_bytes);
    *hasher.finalize().as_bytes()
}
