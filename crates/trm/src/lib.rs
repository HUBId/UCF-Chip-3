#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Load ucf-protocol tool descriptors.

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("registry not found")]
    NotFound,
    #[error("invalid registry entry: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone)]
pub struct ToolDescriptor {
    pub name: String,
    pub version: String,
}

pub trait ToolRegistry: Send + Sync {
    fn load(&self) -> Result<Vec<ToolDescriptor>, RegistryError>;
    fn validate(&self, descriptor: &ToolDescriptor) -> Result<(), RegistryError>;
}

pub struct StaticRegistry {
    entries: Vec<ToolDescriptor>,
}

impl StaticRegistry {
    pub fn new(entries: Vec<ToolDescriptor>) -> Self {
        Self { entries }
    }
}

impl ToolRegistry for StaticRegistry {
    fn load(&self) -> Result<Vec<ToolDescriptor>, RegistryError> {
        Ok(self.entries.clone())
    }

    fn validate(&self, descriptor: &ToolDescriptor) -> Result<(), RegistryError> {
        if descriptor.name.is_empty() {
            return Err(RegistryError::Invalid("missing name".into()));
        }
        Ok(())
    }
}
