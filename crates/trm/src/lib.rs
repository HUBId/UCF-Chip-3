#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap};

use thiserror::Error;
use ucf_protocol::ucf;
use ucf_protocol::{canonical_bytes, digest_proto};

#[derive(Debug, Error)]
pub enum TrmError {
    #[error("missing tool_id")]
    MissingToolId,
    #[error("missing action_id")]
    MissingActionId,
    #[error("action_type unspecified")]
    ActionTypeUnspecified,
    #[error("missing input_schema")]
    MissingInputSchema,
    #[error("missing output_schema")]
    MissingOutputSchema,
    #[error("duplicate entry for {0}/{1}")]
    DuplicateEntry(String, String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ToolLookup<'a> {
    Profile(&'a ucf::v1::ToolActionProfile),
    Suspended,
    Missing,
}

#[derive(Debug, Default)]
pub struct ToolRegistry {
    entries: HashMap<(String, String), ucf::v1::ToolActionProfile>,
    suspended: BTreeSet<(String, String)>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            suspended: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, tap: ucf::v1::ToolActionProfile) -> Result<(), TrmError> {
        validate_tool_action_profile(&tap)?;
        let key = (tap.tool_id.clone(), tap.action_id.clone());
        if self.entries.contains_key(&key) {
            return Err(TrmError::DuplicateEntry(key.0, key.1));
        }
        self.entries.insert(key, tap);
        Ok(())
    }

    pub fn suspend(&mut self, tool_id: &str, action_id: &str) {
        self.suspended
            .insert((tool_id.to_string(), action_id.to_string()));
    }

    pub fn suspend_many<I>(&mut self, pairs: I)
    where
        I: IntoIterator<Item = (String, String)>,
    {
        for (tool_id, action_id) in pairs {
            self.suspended.insert((tool_id, action_id));
        }
    }

    pub fn suspended_actions(&self) -> Vec<(String, String)> {
        self.suspended.iter().cloned().collect()
    }

    pub fn lookup(&self, tool_id: &str, action_id: &str) -> ToolLookup<'_> {
        let key = (tool_id.to_string(), action_id.to_string());
        if self.suspended.contains(&key) {
            return ToolLookup::Suspended;
        }

        match self.entries.get(&key) {
            Some(tap) => ToolLookup::Profile(tap),
            None => ToolLookup::Missing,
        }
    }

    pub fn get(&self, tool_id: &str, action_id: &str) -> Option<&ucf::v1::ToolActionProfile> {
        match self.lookup(tool_id, action_id) {
            ToolLookup::Profile(tap) => Some(tap),
            _ => None,
        }
    }

    pub fn tool_profile_digest(&self, tool_id: &str, action_id: &str) -> Option<ucf::v1::Digest32> {
        self.get(tool_id, action_id)
            .and_then(|tap| tap.profile_digest.clone())
    }

    pub fn build_registry_container(
        &self,
        registry_id: &str,
        registry_version: &str,
        created_at_ms: u64,
    ) -> ucf::v1::ToolRegistryContainer {
        let mut tool_actions: Vec<_> = self
            .entries
            .values()
            .filter(|tap| {
                !self
                    .suspended
                    .contains(&(tap.tool_id.clone(), tap.action_id.clone()))
            })
            .cloned()
            .collect();
        tool_actions.sort_by(|a, b| {
            let tool_cmp = a.tool_id.cmp(&b.tool_id);
            if tool_cmp == std::cmp::Ordering::Equal {
                a.action_id.cmp(&b.action_id)
            } else {
                tool_cmp
            }
        });

        let mut container = ucf::v1::ToolRegistryContainer {
            registry_id: registry_id.to_string(),
            registry_version: registry_version.to_string(),
            created_at_ms,
            tool_actions,
            registry_digest: None,
            proof_receipt_ref: None,
            attestation_sig: None,
        };

        let digest = digest_proto("UCF:HASH:TOOL_REGISTRY", &canonical_bytes(&container));
        container.registry_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });

        container
    }
}

fn validate_tool_action_profile(tap: &ucf::v1::ToolActionProfile) -> Result<(), TrmError> {
    if tap.tool_id.is_empty() {
        return Err(TrmError::MissingToolId);
    }
    if tap.action_id.is_empty() {
        return Err(TrmError::MissingActionId);
    }
    if tap.action_type == ucf::v1::ToolActionType::Unspecified as i32 {
        return Err(TrmError::ActionTypeUnspecified);
    }
    if tap.input_schema.is_none() {
        return Err(TrmError::MissingInputSchema);
    }
    if tap.output_schema.is_none() {
        return Err(TrmError::MissingOutputSchema);
    }
    Ok(())
}

pub fn registry_fixture() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    registry
        .insert(ucf::v1::ToolActionProfile {
            tool_id: "mock.read".to_string(),
            action_id: "get".to_string(),
            action_type: ucf::v1::ToolActionType::Read.into(),
            profile_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            input_schema: Some(ucf::v1::Ref {
                uri: "schema://mock.read/input".to_string(),
                label: "MockReadInput".to_string(),
            }),
            output_schema: Some(ucf::v1::Ref {
                uri: "schema://mock.read/output".to_string(),
                label: "MockReadOutput".to_string(),
            }),
        })
        .expect("valid read profile");

    registry
        .insert(ucf::v1::ToolActionProfile {
            tool_id: "mock.export".to_string(),
            action_id: "render".to_string(),
            action_type: ucf::v1::ToolActionType::Export.into(),
            profile_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            input_schema: Some(ucf::v1::Ref {
                uri: "schema://mock.export/input".to_string(),
                label: "MockExportInput".to_string(),
            }),
            output_schema: Some(ucf::v1::Ref {
                uri: "schema://mock.export/output".to_string(),
                label: "MockExportOutput".to_string(),
            }),
        })
        .expect("valid export profile");

    registry
        .insert(ucf::v1::ToolActionProfile {
            tool_id: "mock.write".to_string(),
            action_id: "apply".to_string(),
            action_type: ucf::v1::ToolActionType::Write.into(),
            profile_digest: Some(ucf::v1::Digest32 {
                value: vec![3u8; 32],
            }),
            input_schema: Some(ucf::v1::Ref {
                uri: "schema://mock.write/input".to_string(),
                label: "MockWriteInput".to_string(),
            }),
            output_schema: Some(ucf::v1::Ref {
                uri: "schema://mock.write/output".to_string(),
                label: "MockWriteOutput".to_string(),
            }),
        })
        .expect("valid write profile");

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_fields() {
        let mut registry = ToolRegistry::new();
        let result = registry.insert(ucf::v1::ToolActionProfile::default());
        assert!(matches!(result, Err(TrmError::MissingToolId)));
    }

    #[test]
    fn rejects_unspecified_action_type() {
        let mut registry = ToolRegistry::new();
        let result = registry.insert(ucf::v1::ToolActionProfile {
            tool_id: "mock.read".to_string(),
            action_id: "get".to_string(),
            action_type: ucf::v1::ToolActionType::Unspecified.into(),
            profile_digest: None,
            input_schema: Some(ucf::v1::Ref::default()),
            output_schema: Some(ucf::v1::Ref::default()),
        });

        assert!(matches!(result, Err(TrmError::ActionTypeUnspecified)));
    }

    #[test]
    fn rejects_missing_schemas() {
        let mut registry = ToolRegistry::new();
        let result = registry.insert(ucf::v1::ToolActionProfile {
            tool_id: "mock.read".to_string(),
            action_id: "get".to_string(),
            action_type: ucf::v1::ToolActionType::Read.into(),
            profile_digest: None,
            input_schema: None,
            output_schema: None,
        });

        assert!(matches!(result, Err(TrmError::MissingInputSchema)));
    }

    #[test]
    fn stores_valid_profile() {
        let registry = registry_fixture();
        let tap = registry.get("mock.read", "get").expect("fixture available");
        assert_eq!(tap.action_id, "get");
        assert_eq!(tap.tool_id, "mock.read");
    }

    #[test]
    fn suspensions_fail_closed() {
        let mut registry = registry_fixture();
        registry.suspend("mock.read", "get");

        assert!(matches!(
            registry.lookup("mock.read", "get"),
            ToolLookup::Suspended
        ));
        assert!(registry.get("mock.read", "get").is_none());
    }

    #[test]
    fn suspended_actions_are_sorted() {
        let mut registry = ToolRegistry::new();
        registry.suspend("tool-b", "action-c");
        registry.suspend("tool-a", "action-b");
        registry.suspend("tool-a", "action-a");

        let suspended = registry.suspended_actions();
        assert_eq!(
            suspended,
            vec![
                ("tool-a".to_string(), "action-a".to_string()),
                ("tool-a".to_string(), "action-b".to_string()),
                ("tool-b".to_string(), "action-c".to_string())
            ]
        );
    }

    #[test]
    fn suspended_actions_are_excluded_from_registry_container() {
        let mut registry = registry_fixture();
        registry.suspend("mock.read", "get");

        let container = registry.build_registry_container("registry", "v1", 123);
        let verbs: Vec<_> = container
            .tool_actions
            .iter()
            .map(|tap| format!("{}/{}", tap.tool_id, tap.action_id))
            .collect();

        assert!(!verbs.contains(&"mock.read/get".to_string()));
        assert_eq!(
            verbs,
            vec![
                "mock.export/render".to_string(),
                "mock.write/apply".to_string()
            ]
        );
    }

    #[test]
    fn deterministic_registry_digest() {
        let registry_one = registry_fixture();
        let registry_two = {
            let mut registry = ToolRegistry::new();
            registry
                .insert(ucf::v1::ToolActionProfile {
                    tool_id: "mock.export".to_string(),
                    action_id: "render".to_string(),
                    action_type: ucf::v1::ToolActionType::Export.into(),
                    profile_digest: Some(ucf::v1::Digest32 {
                        value: vec![2u8; 32],
                    }),
                    input_schema: Some(ucf::v1::Ref {
                        uri: "schema://mock.export/input".to_string(),
                        label: "MockExportInput".to_string(),
                    }),
                    output_schema: Some(ucf::v1::Ref {
                        uri: "schema://mock.export/output".to_string(),
                        label: "MockExportOutput".to_string(),
                    }),
                })
                .expect("valid export profile");
            registry
                .insert(ucf::v1::ToolActionProfile {
                    tool_id: "mock.read".to_string(),
                    action_id: "get".to_string(),
                    action_type: ucf::v1::ToolActionType::Read.into(),
                    profile_digest: Some(ucf::v1::Digest32 {
                        value: vec![1u8; 32],
                    }),
                    input_schema: Some(ucf::v1::Ref {
                        uri: "schema://mock.read/input".to_string(),
                        label: "MockReadInput".to_string(),
                    }),
                    output_schema: Some(ucf::v1::Ref {
                        uri: "schema://mock.read/output".to_string(),
                        label: "MockReadOutput".to_string(),
                    }),
                })
                .expect("valid read profile");
            registry
                .insert(ucf::v1::ToolActionProfile {
                    tool_id: "mock.write".to_string(),
                    action_id: "apply".to_string(),
                    action_type: ucf::v1::ToolActionType::Write.into(),
                    profile_digest: Some(ucf::v1::Digest32 {
                        value: vec![3u8; 32],
                    }),
                    input_schema: Some(ucf::v1::Ref {
                        uri: "schema://mock.write/input".to_string(),
                        label: "MockWriteInput".to_string(),
                    }),
                    output_schema: Some(ucf::v1::Ref {
                        uri: "schema://mock.write/output".to_string(),
                        label: "MockWriteOutput".to_string(),
                    }),
                })
                .expect("valid write profile");
            registry
        };

        let container_one = registry_one.build_registry_container("registry", "v1", 123);
        let container_two = registry_two.build_registry_container("registry", "v1", 123);

        assert_eq!(container_one.registry_digest, container_two.registry_digest);
        assert_eq!(
            canonical_bytes(&container_one),
            canonical_bytes(&container_two)
        );
    }

    #[test]
    fn deterministic_registry_digest_ignores_suspensions_order() {
        let mut registry_one = registry_fixture();
        registry_one.suspend("mock.read", "get");
        registry_one.suspend("mock.write", "apply");

        let mut registry_two = registry_fixture();
        registry_two.suspend("mock.write", "apply");
        registry_two.suspend("mock.read", "get");

        let container_one = registry_one.build_registry_container("registry", "v1", 123);
        let container_two = registry_two.build_registry_container("registry", "v1", 123);

        assert_eq!(container_one.registry_digest, container_two.registry_digest);
        assert_eq!(
            canonical_bytes(&container_one),
            canonical_bytes(&container_two)
        );
        assert_eq!(container_one.tool_actions.len(), 1);
    }
}
