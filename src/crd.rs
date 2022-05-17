// use kube::{api::ListParams, runtime::watcher::Event, ResourceExt};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use thiserror::Error;


#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to patch status VaultSecret: {0}")]
    StatusPatchFailed(#[source] kube::Error),
    #[error("Failed to access Secret: {0}")]
    SecretAccessFailed(#[source] kube::Error),
    #[error("Failed to create Secret: {0}")]
    SecretCreationFailed(#[source] kube::Error),
    #[error("MissingObjectKey: {0}")]
    MissingObjectKey(&'static str),
    #[error("Failed to get data from vault: {0}")]
    VaultRetrieval(#[source] anyhow::Error),
    #[error("Failed to get secret for vault access: {0}")]
    VaultSecretRetrieval(#[source] kube::Error),
    #[error("Failed to update event: {0}")]
    EventWrite(#[source] kube::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("The namespace you are targeting: {0} is not allowed by your creds!")]
    VaultNamespaceNotAllowed(String),
}

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(group = "vault-sync.io", version = "v1", kind = "VaultSecret")]
#[kube(shortname = "vs", namespaced)]
#[kube(status = "VaultSecretStatus")]
pub struct VaultSecretSpec {
    /// Schedule in cron-style syntax
    pub vault: VaultDetails,
    #[serde(rename = "refreshInterval")]
    pub refresh_interval: i64,
    pub target: SecretTarget,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct VaultDetails {
    pub creds: VaultCredsRef,
    pub source: VaultSecretSelector,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct VaultCredsRef {
    pub name: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SecretTarget {
    pub name: String,
    // creation_policy: String,
    // deletion_policy: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct VaultSecretStatus {
    #[serde(rename = "syncStatus")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct VaultSecretSelector {
    pub mount: String,
    pub key: String,
}
