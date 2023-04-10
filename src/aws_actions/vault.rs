use super::{check_response, AwsActionsError, Config};
use chrono::{DateTime, Utc};
use hyper::{body::HttpBody, Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AwsVault {
    pub creation_date: DateTime<Utc>,
    pub last_inventory_date: Option<DateTime<Utc>>,
    pub number_of_archives: i64,
    pub size_in_bytes: i64,
    #[serde(rename(deserialize = "VaultARN"))]
    pub vault_arn: String,
    pub vault_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AwsVaultListResponse {
    pub vault_list: Vec<AwsVault>,
    pub marker: Option<String>,
}

pub async fn list_vaults(config: &Config) -> Result<Vec<AwsVault>, AwsActionsError> {
    let req = super::request(
        config,
        &Method::GET,
        "glacier",
        HashMap::new(),
        "/-/vaults",
        &HashMap::new(),
        Vec::new(),
        false,
    )?;

    let mut resp = tokio::time::timeout(Duration::from_secs(1), req).await??;

    check_response(&mut resp, StatusCode::OK).await?;

    let mut buffer = Vec::new();

    while let Some(chunk) = resp.body_mut().data().await {
        buffer.append(&mut chunk?.to_vec());
    }

    Ok(serde_json::from_slice::<AwsVaultListResponse>(&buffer)?.vault_list)
}
