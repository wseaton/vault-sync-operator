#![forbid(unsafe_code)]

mod crd;
mod telemetry;

use crd::{Error, VaultSecret, VaultSecretStatus};

use anyhow::Result;
use chrono::prelude::*;

use futures::prelude::*;
use k8s_openapi::api::core::v1::Secret;
// use kube::{api::ListParams, runtime::watcher::Event, ResourceExt};
use kube::{
    api::{Api, ListParams, ObjectMeta, Patch, PatchParams},
    runtime::controller::Action,
    runtime::controller::{Context, Controller},
    runtime::events::{Event, EventType, Recorder, Reporter},
    Client, Resource,
};
use serde::Serialize;
use serde_json::json;

use std::{collections::BTreeMap, sync::Arc};
use tokio::{sync::RwLock, time};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::Registry;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, EnvFilter};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs_login::engines::approle::AppRoleLogin;
use vaultrs_login::LoginClient;

/// In-memory reconciler state exposed on /
#[derive(Clone, Serialize)]
pub struct State {
    #[serde(skip)]
    pub reporter: Reporter,
}
impl State {
    fn new() -> Self {
        State {
            reporter: "vault-sync".into(),
        }
    }
}

/// Function to calculate if we should refresh an instance of a secret or not based on some interval.
fn should_update(secret: Option<Secret>, refresh_interval: i64) -> bool {
    if let Some(s) = secret {
        let fields = s.metadata.managed_fields;
        if let Some(f) = fields {
            let latest = f.iter().find(|x| {
                x.manager == Some("vault-syncer.kube-rt.vault-sync.io".to_string())
                    && x.operation == Some("Apply".to_string())
            });
            if let Some(e) = latest {
                if let Some(t) = &e.time {
                    t.0 + chrono::Duration::seconds(refresh_interval) <= Utc::now()
                } else {
                    true
                }
            } else {
                true
            }
        } else {
            tracing::info!("Secret exists but no managed fields, we will update.");
            true
        }
    } else {
        tracing::info!("Secret doesn't exist, we need to create it.");
        true
    }
}

struct VaultConf {
    address: String,
    role_id: String,
    secret_id: String,
    allowed_namespaces: Vec<String>,
}

fn load_vault_secret(secret: Secret) -> Result<VaultConf> {
    if let Some(bd) = secret.data {
        let address = bd
            .get("VAULT_ADDR")
            .map(|x| String::from_utf8(x.clone().0).unwrap())
            .unwrap();
        let role_id = bd
            .get("VAULT_APPROLE_ID")
            .map(|x| String::from_utf8(x.clone().0).unwrap())
            .unwrap();
        let secret_id = bd
            .get("VAULT_SECRET_ID")
            .map(|x| String::from_utf8(x.clone().0).unwrap())
            .unwrap();
        let allowed_namespaces = bd
            .get("ALLOWED_TARGET_NAMESPACES")
            .map(|x| String::from_utf8(x.clone().0).unwrap())
            .unwrap_or_else(|| "".to_string())
            .split(",")
            .map(|s| s.to_owned())
            .collect();
        
        Ok(VaultConf {
            address,
            role_id,
            secret_id,
            allowed_namespaces,
        })
    } else {
        panic!("Nope!")
    }
}

#[tracing::instrument(skip(ctx, generator), fields(trace_id))]
async fn patch_secret(generator: Arc<VaultSecret>, ctx: Context<Data>) -> Result<(), Error> {
    let target_namespace = generator
        .metadata
        .namespace
        .as_ref()
        .ok_or(Error::MissingObjectKey(".metadata.namespace"))?;
    let client = ctx.get_ref().client.clone();
    let mount = generator.spec.vault.source.mount.as_ref();
    let key = generator.spec.vault.source.key.as_ref();

    let reporter = ctx.get_ref().state.read().await.reporter.clone();
    let recorder = Recorder::new(client.clone(), reporter, generator.object_ref(&()));
    let target_secret_api = Api::<Secret>::namespaced(client.clone(), target_namespace);

    let secret = target_secret_api
        .get_opt(&generator.spec.target.name)
        .await
        .map_err(Error::SecretAccessFailed)?;

    // only send event if a secret is being synced
    recorder
        .publish(Event {
            type_: EventType::Normal,
            reason: "UpdateSecret".into(),
            note: Some(format!("Updating secret: {}", &generator.spec.target.name)),
            action: "Reconciling".into(),
            secondary: secret.map(|s| s.object_ref(&())),
        })
        .await
        .map_err(Error::EventWrite)?;

    // look up the data we need from vault to get access to our secret.
    let source_creds_secret_api = Api::<Secret>::namespaced(
        client.clone(),
        generator.spec.vault.creds.namespace.as_ref(),
    );
    let vault_access_secret = source_creds_secret_api
        .get(generator.spec.vault.creds.name.as_ref())
        .await
        .map_err(Error::VaultSecretRetrieval)?;

    let vault_conf =
        load_vault_secret(vault_access_secret).map_err(Error::Other)?;

    // check and make sure the namespace is 'allowed' to be targeted by the creds
    // to prevent a snooping attack 
    if !vault_conf.allowed_namespaces.contains(target_namespace) {
        tracing::error!("Not allowed! Cross-namespace access was not allowlisted!");
        return Err(Error::VaultNamespaceNotAllowed(target_namespace.to_owned()))
    } else {
        tracing::info!("Access is allowed for this cred/target pair.")
    }
    // actually get our vault data
    let data = get_secret(vault_conf, mount, key)
        .await
        .map_err(Error::VaultRetrieval)?;

    let labels = if let Some(l) = &mut generator.metadata.labels.clone() {
        l.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "vault-sync".to_string(),
        );
        Some(l.to_owned())
    } else {
        let mut l: BTreeMap<String, String> = BTreeMap::new();
        l.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "vault-sync".to_string(),
        );
        Some(l.to_owned())
    };

    let secret: Secret = Secret {
        data: None,
        immutable: Some(true),
        metadata: ObjectMeta {
            name: Some(generator.spec.target.name.clone()),
            namespace: Some(target_namespace.to_string()),
            owner_references: Some(vec![generator.controller_owner_ref(&()).unwrap()]),
            labels,
            annotations: generator.metadata.annotations.clone(),
            ..ObjectMeta::default()
        },
        string_data: Some(data),
        type_: Some("Opaque".to_string()),
    };

    target_secret_api
        .patch(
            secret
                .metadata
                .name
                .as_ref()
                .ok_or(Error::MissingObjectKey(".metadata.name"))?,
            &PatchParams::apply("vault-syncer.kube-rt.vault-sync.io"),
            &Patch::Apply(&secret),
        )
        .await
        .map_err(Error::SecretCreationFailed)?;

    Ok(())
}

#[tracing::instrument(skip(ctx, generator), fields(trace_id))]
async fn reconcile(generator: Arc<VaultSecret>, ctx: Context<Data>) -> Result<Action, Error> {
    let client = ctx.get_ref().client.clone();
    let target_namespace = generator
        .metadata
        .namespace
        .as_ref()
        .ok_or(Error::MissingObjectKey(".metadata.namespace"))?;

    let name = generator
        .metadata
        .name
        .as_ref()
        .ok_or(Error::MissingObjectKey(".metadata.name"))?;

    // let name = ResourceExt::name(generator.as_ref());
    let target_secret_api = Api::<Secret>::namespaced(client.clone(), target_namespace);
    let secret = target_secret_api
        .get_opt(&generator.spec.target.name)
        .await
        .map_err(Error::SecretAccessFailed)?;

    if should_update(secret.clone(), generator.spec.refresh_interval) {
        let res = patch_secret(generator.clone(), ctx.clone()).await;
        match res {
            Ok(_) => {
                let vault_secrets: Api<VaultSecret> =
                    Api::namespaced(client.clone(), target_namespace);
                let new_status = Patch::Apply(json!({
                    "apiVersion": "vault-sync.eda.io/v1",
                    "kind": "VaultSecret",
                    "status": VaultSecretStatus {sync_status: Some("Success".to_string()), trace_id:  None}
                }));
                let ps = PatchParams::apply("vault-syncer.kube-rt.vault-sync.io").force();
                let _vsp = vault_secrets
                    .patch_status(name, &ps, &new_status)
                    .await
                    .map_err(Error::StatusPatchFailed)?;
            }
            Err(e) => {
                tracing::error!("Error patching secret {:?}", e);
                // throw an event
                let reporter = ctx.get_ref().state.read().await.reporter.clone();
                let recorder = Recorder::new(client.clone(), reporter, generator.object_ref(&()));
                recorder
                    .publish(Event {
                        type_: EventType::Warning,
                        reason: "UpdateSecret".into(),
                        note: Some(format!("Error: {:?}", e)),
                        action: "Reconciling".into(),
                        secondary: secret.map(|s| s.object_ref(&())),
                    })
                    .await
                    .map_err(Error::EventWrite)?;

                // update the CR w/ the status
                let vault_secrets: Api<VaultSecret> =
                    Api::namespaced(client.clone(), target_namespace);
                // TODO: fix this so it doesn't hot loop if we provide a `trace_id`
                // can we provide just the first trace_id for a string of failures to make the reconcile idempotent?
                // let current_span = tracing::span::Span::current();
                let new_status = Patch::Apply(json!({
                    "apiVersion": "vault-sync.eda.io/v1",
                    "kind": "VaultSecret",
                    "status": VaultSecretStatus {sync_status: Some("Failed".to_string()), trace_id: None }//trace_id: Some(format!("{:?}", current_span.id())) }
                }));
                let ps = PatchParams::apply("vault-syncer.kube-rt.vault-sync.io").force();
                let _vsp = vault_secrets
                    .patch_status(name, &ps, &new_status)
                    .await
                    .map_err(Error::StatusPatchFailed)?;

                return Ok(Action::await_change());
            }
        }
    }

    // TODO: properly error handle this
    Ok(Action::requeue(tokio::time::Duration::from_secs(
        generator.spec.refresh_interval.try_into().unwrap(),
    )))
}

async fn init_telemetry() -> Result<()> {
    let tracer = telemetry::init_tracer().await?;
    // Create a `tracing` layer using the Jaeger tracer
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    // Filter based on level - trace, debug, info, warn, error
    // Tunable via `RUST_LOG` env variable
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    let formatting_layer = BunyanFormattingLayer::new("vault-sync".into(), std::io::stdout);

    let subscriber = Registry::default()
        .with(env_filter)
        .with(telemetry)
        .with(JsonStorageLayer)
        .with(formatting_layer);

    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_telemetry().await?;

    let runtime = Client::try_default().await.expect("Create client");

    let vs_api = Api::<VaultSecret>::all(runtime.clone());
    let s_api: Api<Secret> = Api::<Secret>::all(runtime.clone());

    Controller::new(vs_api, ListParams::default())
        .owns(
            s_api,
            ListParams::default().labels("app.kubernetes.io/managed-by=vault-sync"),
        )
        .shutdown_on_signal()
        .run(
            reconcile,
            error_policy,
            Context::new(Data {
                client: runtime.clone(),
                state: Arc::new(RwLock::new(State::new())),
            }),
        )
        .for_each(|res| async move {
            match res {
                Ok(o) => tracing::info!("reconciled {:?}", o),
                Err(e) => tracing::error!("reconcile failed: {:?}", e),
            }
        })
        .await;
    tracing::info!("controller terminated");

    Ok(())
}

async fn get_secret(
    conf: VaultConf,
    mount: &str,
    path: &str,
) -> Result<BTreeMap<String, String>, anyhow::Error> {
    let mut client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(conf.address)
            .build()?,
    )?;
    let login = AppRoleLogin { role_id: conf.role_id, secret_id: conf.secret_id };
    client.login("approle", &login).await?;
    // Token is automatically set to cli
    use vaultrs::kv2;
    let secret: BTreeMap<String, String> = kv2::read(&client, mount, path).await?;
    Ok(secret)
}

struct Data {
    client: Client,
    state: Arc<RwLock<State>>,
}

/// TODO: exponential backoff?
///    - https://docs.rs/backoff/0.4.0/backoff/backoff/trait.Backoff.html#tymethod.next_backoff
fn error_policy(error: &Error, _ctx: Context<Data>) -> Action {
    tracing::error!("Error occured: {}", error);
    Action::await_change()
}

#[derive(Copy, Clone, Debug)]
struct Timeout(time::Duration);

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("invalid duration")]
struct InvalidTimeout;

impl std::str::FromStr for Timeout {
    type Err = InvalidTimeout;

    fn from_str(s: &str) -> Result<Self, InvalidTimeout> {
        let re = regex::Regex::new(r"^\s*(\d+)(ms|s|m)?\s*$").expect("duration regex");
        let cap = re.captures(s).ok_or(InvalidTimeout)?;
        let magnitude = cap[1].parse().map_err(|_| InvalidTimeout)?;
        let t = match cap.get(2).map(|m| m.as_str()) {
            None if magnitude == 0 => time::Duration::from_millis(0),
            Some("ms") => time::Duration::from_millis(magnitude),
            Some("s") => time::Duration::from_secs(magnitude),
            Some("m") => time::Duration::from_secs(magnitude * 60),
            _ => return Err(InvalidTimeout),
        };
        Ok(Self(t))
    }
}

async fn _init_timeout<F: Future>(deadline: Option<time::Instant>, future: F) -> Result<F::Output> {
    if let Some(deadline) = deadline {
        return time::timeout_at(deadline, future).await.map_err(Into::into);
    }

    Ok(future.await)
}
