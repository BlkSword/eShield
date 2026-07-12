use eshield_common::IpKey;
use serde::{Deserialize, Serialize};

mod ip_key_serde {
    use eshield_common::IpKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(remote = "IpKey")]
    struct IpKeyDef {
        family: u8,
        addr: [u8; 16],
        padding: [u8; 15],
    }

    pub fn serialize<S: Serializer>(ip: &IpKey, serializer: S) -> Result<S::Ok, S::Error> {
        IpKeyDef::serialize(ip, serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<IpKey, D::Error> {
        IpKeyDef::deserialize(deserializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPolicy {
    #[serde(with = "ip_key_serde")]
    pub ip: IpKey,
    pub reason: u8,
    pub hit_count: u32,
    pub trust_score: u32,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub source_nodes: Vec<String>,
    pub ttl_s: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPush {
    pub node_name: String,
    pub policies: Vec<NodePolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePolicy {
    #[serde(with = "ip_key_serde")]
    pub ip: IpKey,
    pub reason: u8,
    pub hit_count: u32,
    pub trust_score: u32,
    pub blocked_until_ns: u64,
    pub ttl_s: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPull {
    pub policies: Vec<SharedPolicy>,
    pub cursor: String,
    #[serde(default)]
    pub deleted: Vec<IpKey>,
    #[serde(default)]
    pub deleted_cursor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDelete {
    pub node_name: String,
    pub ips: Vec<IpKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedPolicies {
    pub ips: Vec<IpKey>,
    pub cursor: String,
}

/// 端口 ACL 规则项。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAclItem {
    pub protocol: String,
    pub dport: String,
    pub action: String,
}

/// L7 指纹模式。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7PatternConfig {
    pub pattern: String,
    #[serde(default)]
    pub mask: Option<String>,
}

/// 防护项目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionProject {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub protocol: String,
    pub dport: String,
    #[serde(default)]
    pub target_ips: Vec<String>,
    #[serde(default)]
    pub enabled_modules: Vec<String>,
    #[serde(default = "default_project_action")]
    pub action: String,
}

fn default_project_action() -> String {
    "defend".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBundle {
    pub port_acl: Vec<PortAclItem>,
    pub l7_patterns: Vec<L7PatternConfig>,
    pub protection_projects: Vec<ProtectionProject>,
    pub updated_at_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesResponse {
    pub rules: Option<RuleBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    pub node_name: String,
    pub stats: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub name: String,
    pub last_seen_ns: u64,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodesResponse {
    pub nodes: Vec<NodeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub policy_count: u64,
    pub node_count: usize,
    pub online_node_count: usize,
}
