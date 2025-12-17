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
        pub struct ReasonCodes {
            #[prost(string, repeated, tag = "1")]
            pub codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
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
        pub enum DecisionForm {
            Unspecified = 0,
            Allow = 1,
            Deny = 2,
            RequireApproval = 3,
        }
        impl DecisionForm {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    DecisionForm::Unspecified => "DECISION_FORM_UNSPECIFIED",
                    DecisionForm::Allow => "DECISION_FORM_ALLOW",
                    DecisionForm::Deny => "DECISION_FORM_DENY",
                    DecisionForm::RequireApproval => "DECISION_FORM_REQUIRE_APPROVAL",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "DECISION_FORM_UNSPECIFIED" => Some(Self::Unspecified),
                    "DECISION_FORM_ALLOW" => Some(Self::Allow),
                    "DECISION_FORM_DENY" => Some(Self::Deny),
                    "DECISION_FORM_REQUIRE_APPROVAL" => Some(Self::RequireApproval),
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
        }
        impl RecordType {
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    RecordType::Unspecified => "RECORD_TYPE_UNSPECIFIED",
                    RecordType::Policy => "RECORD_TYPE_POLICY",
                    RecordType::Proof => "RECORD_TYPE_PROOF",
                    RecordType::Audit => "RECORD_TYPE_AUDIT",
                }
            }
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "RECORD_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                    "RECORD_TYPE_POLICY" => Some(Self::Policy),
                    "RECORD_TYPE_PROOF" => Some(Self::Proof),
                    "RECORD_TYPE_AUDIT" => Some(Self::Audit),
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
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ConstraintsDelta {
            #[prost(string, repeated, tag = "1")]
            pub constraints_added: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            #[prost(string, repeated, tag = "2")]
            pub constraints_removed: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
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
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PvgsReceipt {
            #[prost(enumeration = "ReceiptStatus", tag = "1")]
            pub status: i32,
            #[prost(message, optional, tag = "2")]
            pub program_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "3")]
            pub proof_digest: ::core::option::Option<Digest32>,
            #[prost(message, optional, tag = "4")]
            pub signer: ::core::option::Option<Signature>,
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
