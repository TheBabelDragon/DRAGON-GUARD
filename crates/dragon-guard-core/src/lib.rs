//! DRAGON//GUARD core — observation identifiers, scope enforcement, registry (std only).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub const SCHEMA_VERSION: &str = "dragon-guard/observation/0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationType {
    AssetDiscovery,
    Service,
    Protocol,
    Configuration,
    Vulnerability,
    BehavioralAnomaly,
    Remediation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceRef {
    pub id: String,
    pub kind: String,
    pub path: Option<String>,
    pub content_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub observation_id: String,
    pub schema_version: String,
    pub asset_id: String,
    pub node_id: String,
    pub source_tool: String,
    pub observation_type: ObservationType,
    pub timestamp: String,
    pub clock_source: String,
    pub protocol: Option<String>,
    pub target: String,
    pub severity: Severity,
    pub confidence: f64,
    pub evidence_refs: Vec<EvidenceRef>,
    pub execution_id: Option<String>,
}

impl Observation {
    pub fn validate(&self) -> Result<(), String> {
        if self.observation_id.is_empty() {
            return Err("observation_id required".into());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema_version {} (want {})",
                self.schema_version, SCHEMA_VERSION
            ));
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err("confidence must be in [0,1]".into());
        }
        if self.asset_id.is_empty() || self.target.is_empty() {
            return Err("asset_id and target required".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Asset {
    pub asset_id: String,
    pub name: String,
    pub addresses: Vec<String>,
    pub hostnames: Vec<String>,
    pub authorized: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Registry {
    pub assets: BTreeMap<String, Asset>,
    pub observations: Vec<Observation>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_asset(&mut self, asset: Asset) {
        self.assets.insert(asset.asset_id.clone(), asset);
    }

    pub fn add_observation(&mut self, obs: Observation) -> Result<(), String> {
        obs.validate()?;
        self.observations.push(obs);
        Ok(())
    }
}

/// Explicit allowlist scope. Default deny.
#[derive(Debug, Clone, Default)]
pub struct ScopePolicy {
    pub allow_hosts: BTreeSet<String>,
    pub allow_cidrs: Vec<String>,
    pub require_authorized_asset: bool,
}

impl ScopePolicy {
    pub fn lab_localhost() -> Self {
        let mut s = Self::default();
        s.allow_hosts.insert("127.0.0.1".into());
        s.allow_hosts.insert("localhost".into());
        s.allow_hosts.insert("::1".into());
        s.allow_cidrs.push("127.0.0.0/8".into());
        s
    }

    pub fn normalize_target(host: &str) -> Result<String, String> {
        let h = host.trim();
        if h.is_empty() {
            return Err("empty target".into());
        }
        if h.chars().all(|c| c.is_ascii_digit()) {
            return Err("integer-form IP targets are not allowed".into());
        }
        if h.contains("0x") || h.contains("0X") {
            return Err("hex-form IP targets are not allowed".into());
        }
        if let Ok(ip) = IpAddr::from_str(h) {
            return Ok(ip.to_string());
        }
        let hn = h.trim_end_matches('.').to_lowercase();
        if hn.is_empty() || hn.contains(' ') {
            return Err("invalid hostname".into());
        }
        Ok(hn)
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        let host = host.trim().to_lowercase();
        if self.allow_hosts.iter().any(|h| h.to_lowercase() == host) {
            return true;
        }
        if let Ok(ip) = IpAddr::from_str(&host) {
            return self.ip_in_cidrs(ip);
        }
        false
    }

    fn ip_in_cidrs(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(addr) = ip else {
            return false;
        };
        let bits = u32::from(addr);
        for cidr in &self.allow_cidrs {
            if let Some((net, prefix)) = parse_cidr_v4(cidr) {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                if bits & mask == net & mask {
                    return true;
                }
            }
        }
        false
    }

    pub fn authorize_target(&self, raw: &str) -> Result<String, String> {
        let norm = Self::normalize_target(raw)?;
        if self.is_host_allowed(&norm) {
            return Ok(norm);
        }
        Err(format!("target out of scope: {raw}"))
    }
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
    let (ip, pfx) = cidr.split_once('/')?;
    let addr = Ipv4Addr::from_str(ip).ok()?;
    let prefix: u32 = pfx.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((u32::from(addr), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_localhost_allowed() {
        let s = ScopePolicy::lab_localhost();
        assert!(s.authorize_target("127.0.0.1").is_ok());
        assert!(s.authorize_target("localhost").is_ok());
    }

    #[test]
    fn scope_rejects_external() {
        let s = ScopePolicy::lab_localhost();
        assert!(s.authorize_target("8.8.8.8").is_err());
        assert!(s.authorize_target("evil.example").is_err());
    }

    #[test]
    fn rejects_integer_ip_form() {
        assert!(ScopePolicy::normalize_target("2130706433").is_err());
    }

    #[test]
    fn observation_schema() {
        let obs = Observation {
            observation_id: "obs-1".into(),
            schema_version: SCHEMA_VERSION.into(),
            asset_id: "a1".into(),
            node_id: "n1".into(),
            source_tool: "nmap".into(),
            observation_type: ObservationType::Service,
            timestamp: "2026-01-01T00:00:00Z".into(),
            clock_source: "wall".into(),
            protocol: Some("tcp".into()),
            target: "127.0.0.1".into(),
            severity: Severity::Info,
            confidence: 0.9,
            evidence_refs: vec![],
            execution_id: None,
        };
        assert!(obs.validate().is_ok());
    }

    #[test]
    fn observation_rejects_bad_confidence() {
        let mut obs = Observation {
            observation_id: "obs-1".into(),
            schema_version: SCHEMA_VERSION.into(),
            asset_id: "a1".into(),
            node_id: "n1".into(),
            source_tool: "nmap".into(),
            observation_type: ObservationType::Service,
            timestamp: "t".into(),
            clock_source: "wall".into(),
            protocol: None,
            target: "127.0.0.1".into(),
            severity: Severity::Info,
            confidence: 1.5,
            evidence_refs: vec![],
            execution_id: None,
        };
        assert!(obs.validate().is_err());
        obs.confidence = 0.5;
        obs.schema_version = "other".into();
        assert!(obs.validate().is_err());
    }
}
