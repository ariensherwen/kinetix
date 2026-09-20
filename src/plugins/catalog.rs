//! Official plugin catalog and publisher trust metadata.
//!
//! The embedded catalog is discovery metadata. Publisher keys live in a
//! separate embedded trust store so changing a catalog entry cannot introduce a
//! new trusted signing key.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Catalog {
    pub schema_version: u32,
    #[serde(default)]
    pub plugins: Vec<CatalogPlugin>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CatalogPlugin {
    pub id: String,
    pub name: String,
    pub description: String,
    pub publisher: String,
    #[serde(default)]
    pub official: bool,
    pub homepage: String,
    pub latest_version: String,
    pub artifact_name: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub installable: bool,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub distribution: Option<CatalogDistribution>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CatalogDistribution {
    pub url: String,
    pub sha256: String,
    pub publisher_key_id: String,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublisherTrustStore {
    pub schema_version: u32,
    #[serde(default)]
    pub publishers: Vec<TrustedPublisher>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustedPublisher {
    pub id: String,
    pub publisher: String,
    pub algorithm: String,
    pub public_key_base64: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

pub fn embedded_catalog() -> Result<Catalog> {
    let catalog: Catalog = serde_json::from_str(include_str!("../../plugins/catalog.json"))
        .context("parsing embedded plugin catalog")?;
    if catalog.schema_version != 1 {
        bail!(
            "unsupported plugin catalog schema_version {}",
            catalog.schema_version
        );
    }
    Ok(catalog)
}

pub fn embedded_trust_store() -> Result<PublisherTrustStore> {
    let store: PublisherTrustStore =
        serde_json::from_str(include_str!("../../plugins/trusted-publishers.json"))
            .context("parsing embedded plugin publisher trust store")?;
    if store.schema_version != 1 {
        bail!(
            "unsupported plugin publisher trust schema_version {}",
            store.schema_version
        );
    }
    Ok(store)
}

pub fn find_plugin(id: &str) -> Result<CatalogPlugin> {
    embedded_catalog()?
        .plugins
        .into_iter()
        .find(|plugin| plugin.id == id)
        .ok_or_else(|| anyhow!("catalog plugin '{id}' not found"))
}

pub fn trusted_key(
    store: &PublisherTrustStore,
    plugin: &CatalogPlugin,
) -> Result<Option<[u8; 32]>> {
    let Some(distribution) = &plugin.distribution else {
        return Ok(None);
    };
    let Some(publisher) = store
        .publishers
        .iter()
        .find(|publisher| publisher.id == distribution.publisher_key_id && publisher.enabled)
    else {
        return Ok(None);
    };
    if publisher.publisher != plugin.publisher {
        bail!(
            "publisher key '{}' belongs to '{}' but catalog plugin '{}' declares '{}'",
            publisher.id,
            publisher.publisher,
            plugin.id,
            plugin.publisher
        );
    }
    if publisher.algorithm != "ed25519" {
        bail!(
            "publisher key '{}' uses unsupported algorithm '{}'",
            publisher.id,
            publisher.algorithm
        );
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(publisher.public_key_base64.trim())
        .context("decoding trusted publisher key")?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("trusted publisher Ed25519 key must be exactly 32 bytes"))?;
    Ok(Some(key))
}

pub fn install_ready(plugin: &CatalogPlugin, store: &PublisherTrustStore) -> Result<bool> {
    if !plugin.installable {
        return Ok(false);
    }
    let Some(distribution) = &plugin.distribution else {
        return Ok(false);
    };
    if distribution.url.is_empty()
        || distribution.sha256.len() != 64
        || distribution.publisher_key_id.is_empty()
        || distribution.allowed_hosts.is_empty()
    {
        return Ok(false);
    }
    Ok(trusted_key(store, plugin)?.is_some())
}

pub fn validate_download_url(distribution: &CatalogDistribution, url: &url::Url) -> Result<()> {
    if url.scheme() != "https" {
        bail!("catalog plugin artifacts must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("catalog plugin artifact URLs may not contain userinfo");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("catalog plugin artifact URL has no host"))?
        .to_ascii_lowercase();
    if !distribution
        .allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
    {
        bail!("catalog artifact host '{host}' is not in allowed_hosts");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_metadata_is_valid() {
        let catalog = embedded_catalog().unwrap();
        let trust = embedded_trust_store().unwrap();
        assert_eq!(catalog.schema_version, 1);
        assert_eq!(trust.schema_version, 1);
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.id == "dev.kinetix.antigravity-oauth"));
    }

    #[test]
    fn current_antigravity_entry_fails_closed_until_signed_distribution_exists() {
        let plugin = find_plugin("dev.kinetix.antigravity-oauth").unwrap();
        let trust = embedded_trust_store().unwrap();
        assert!(!install_ready(&plugin, &trust).unwrap());
    }

    #[test]
    fn download_url_requires_https_and_allowlisted_host() {
        let distribution = CatalogDistribution {
            url: "https://github.com/example/plugin.kxp".into(),
            sha256: "0".repeat(64),
            publisher_key_id: "test".into(),
            allowed_hosts: vec!["github.com".into()],
        };
        validate_download_url(
            &distribution,
            &url::Url::parse("https://github.com/example/plugin.kxp").unwrap(),
        )
        .unwrap();
        assert!(validate_download_url(
            &distribution,
            &url::Url::parse("http://github.com/example/plugin.kxp").unwrap(),
        )
        .is_err());
        assert!(validate_download_url(
            &distribution,
            &url::Url::parse("https://evil.example/plugin.kxp").unwrap(),
        )
        .is_err());
    }
}
