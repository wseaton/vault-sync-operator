use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Secret;
use anyhow::Result;

use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs_login::engines::approle::AppRoleLogin;
use vaultrs_login::LoginClient;

pub struct VaultConf {
    pub address: String,
    pub role_id: String,
    pub secret_id: String,
    pub allowed_namespaces: Vec<String>,
}

pub fn load_vault_secret(secret: Secret) -> Result<VaultConf> {
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
            .split(',')
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

pub async fn get_secret(
    conf: VaultConf,
    mount: &str,
    path: &str,
) -> Result<BTreeMap<String, String>, anyhow::Error> {
    let mut client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(conf.address)
            .build()?,
    )?;
    let login = AppRoleLogin {
        role_id: conf.role_id,
        secret_id: conf.secret_id,
    };
    client.login("approle", &login).await?;
    // Token is automatically set to cli
    use vaultrs::kv2;
    let secret: BTreeMap<String, String> = kv2::read(&client, mount, path).await?;
    Ok(secret)
}
