mod adaptive;
mod config;
mod event_consumer;
mod state;
mod tui;
mod web;

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{lpm_trie::Key as LpmKey, Array, HashMap as LruHashMap, LpmTrie},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::{Parser, Subcommand};
use eshield_common::{rules, BlockEntry, CookieSecret, L7Pattern, RateLimitConfig, RuntimeConfig, WhitelistKey};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::signal;
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tracing::{info, warn};
use rand::Rng;

use crate::{
    config::{parse_ip, Config},
    state::AppStateInner,
};

#[derive(Debug, Parser)]
#[command(name = "eshield")]
#[command(about = "eBPF/XDP host-level CC defense shield")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the XDP shield
    Start {
        /// Path to config file
        #[arg(short, long, default_value = "/etc/eshield/config.toml")]
        config: String,
    },
    /// Show current status
    Status,
    /// Launch standalone TUI dashboard
    Tui {
        /// eShield HTTP API endpoint
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => start(&config).await,
        Commands::Status => {
            println!("eShield status command is not implemented yet");
            Ok(())
        }
        Commands::Tui { endpoint } => tui::run(endpoint).await,
    }
}

async fn start(config_path: &str) -> anyhow::Result<()> {
    let config = Config::from_file(config_path).unwrap_or_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level)),
        )
        .init();

    info!("loading eShield eBPF program");

    // eBPF 统一使用 release 产物嵌入，避免 debug 构建因 overflow-checks panic 代码导致 bpf-linker 失败
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/eshield"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // 初始化运行时配置
    init_config_map(&mut ebpf, &config)?;

    // 初始化 SYN Cookie 密钥
    init_cookie_secrets(&mut ebpf)?;

    // 初始化速率限制参数
    init_rate_limit_map(&mut ebpf, &config)?;

    // 初始化 L7 指纹模式
    init_l7_patterns_map(&mut ebpf, &config)?;

    // 加载用户配置中的黑名单
    let mut static_blacklist = init_blacklist_map(&mut ebpf, &config)?;

    // 加载用户配置中的白名单
    let mut current_whitelist = init_whitelist_map(&mut ebpf, &config)?;

    let program: &mut Xdp = ebpf
        .program_mut("eshield")
        .context("program 'eshield' not found")?
        .try_into()?;
    program.load()?;

    // Try Native (driver) mode first, fall back to Generic (SKB) mode.
    match program.attach(&config.interface, XdpFlags::DRV_MODE) {
        Ok(_) => info!("attached XDP in DRV (native) mode on {}", config.interface),
        Err(e) => {
            warn!("native XDP attach failed ({}), trying generic mode", e);
            program
                .attach(&config.interface, XdpFlags::SKB_MODE)
                .context("failed to attach XDP program")?;
            info!("attached XDP in SKB (generic) mode on {}", config.interface);
        }
    }

    let state = Arc::new(AppStateInner::new());
    let adaptive = Arc::new(adaptive::AdaptiveEngine::new(config.adaptive.clone()));

    // 启动 Web 观测面板
    let web_port = if config.web_port == 0 { 8443 } else { config.web_port };
    let _web_handle = {
        let stats = state.stats.clone();
        tokio::spawn(async move {
            if let Err(e) = web::run(stats, web_port).await {
                warn!("web server exited: {}", e);
            }
        })
    };

    // Ebpf 状态由事件消费任务与热加载共享
    let ebpf = Arc::new(tokio::sync::Mutex::new(ebpf));

    // 启动 SYN Cookie 密钥轮换任务
    let rotator_handle = {
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            rotate_cookie_secrets(ebpf).await;
        })
    };

    // 启动事件消费任务：周期性获取 Ebpf 锁消费事件，避免阻塞热加载
    let event_handle = {
        let stats = state.stats.clone();
        let adaptive = adaptive.clone();
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            loop {
                let mut guard = ebpf.lock().await;
                match event_consumer::run(stats.clone(), adaptive.clone(), &mut guard).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("event consumer exited: {}", e);
                        break;
                    }
                }
                // 释放锁后短暂让出，使热加载有机会执行
            }
        })
    };

    let mut sighup = unix_signal(SignalKind::hangup())?;

    info!(
        "eShield is running on {}, press Ctrl-C to stop, send SIGHUP to reload config",
        config.interface
    );

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("shutting down eShield");
                break;
            }
            _ = sighup.recv() => {
                info!("received SIGHUP, reloading config");
                let mut guard = ebpf.lock().await;
                match reload_config(&mut guard, config_path, &mut current_whitelist, &mut static_blacklist).await {
                    Ok(()) => info!("config reloaded successfully"),
                    Err(e) => warn!("config reload failed: {}", e),
                }
                // 锁在此处释放，事件消费任务继续
            }
        }
    }

    event_handle.abort();
    rotator_handle.abort();
    let _ = event_handle.await;
    let _ = rotator_handle.await;

    Ok(())
}

fn init_config_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut config_array: Array<_, RuntimeConfig> = ebpf
        .map_mut("CONFIG")
        .context("CONFIG map not found")?
        .try_into()?;
    config_array.set(
        0,
        RuntimeConfig {
            rate_limit_enabled: u8::from(config.rate_limit.enabled),
            syn_proxy_enabled: u8::from(config.syn_proxy.enabled),
            l7_scan_enabled: u8::from(config.l7_scan.enabled),
            padding: [0; 5],
        },
        0,
    )?;
    Ok(())
}

fn init_rate_limit_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut rate_cfg: Array<_, RateLimitConfig> = ebpf
        .map_mut("RATE_LIMIT_CFG")
        .context("RATE_LIMIT_CFG map not found")?
        .try_into()?;
    rate_cfg.set(
        0,
        RateLimitConfig {
            threshold: config.rate_limit.threshold,
            tick_ms: config.rate_limit.tick_ms,
            decay_num: config.rate_limit.decay_num,
            decay_den: config.rate_limit.decay_den,
            block_duration_s: config.rate_limit.block_duration_s,
        },
        0,
    )?;
    Ok(())
}

fn init_l7_patterns_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut patterns: Array<_, L7Pattern> = ebpf
        .map_mut("L7_PATTERNS")
        .context("L7_PATTERNS map not found")?
        .try_into()?;

    for (i, pat_cfg) in config.l7_scan.patterns.iter().enumerate().take(16) {
        let pattern_bytes = pat_cfg.pattern.as_bytes();
        if pattern_bytes.len() > 8 {
            anyhow::bail!("L7 pattern {} exceeds 8 bytes", i);
        }

        let mut sig = [0u8; 8];
        let mut mask = [0u8; 8];

        if let Some(mask_str) = &pat_cfg.mask {
            let mask_bytes = mask_str.as_bytes();
            if mask_bytes.len() != pattern_bytes.len() {
                anyhow::bail!("L7 pattern {} mask length mismatch", i);
            }
            sig[..pattern_bytes.len()].copy_from_slice(pattern_bytes);
            mask[..mask_bytes.len()].copy_from_slice(mask_bytes);
        } else {
            sig[..pattern_bytes.len()].copy_from_slice(pattern_bytes);
            mask[..pattern_bytes.len()].fill(0xff);
        }

        patterns.set(
            i as u32,
            L7Pattern {
                signature: u64::from_le_bytes(sig),
                mask: u64::from_le_bytes(mask),
                length: pattern_bytes.len() as u8,
                action: 0, // DROP
            },
            0,
        )?;
    }

    Ok(())
}

fn init_blacklist_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<Vec<u32>> {
    let mut blacklist: LruHashMap<_, u32, BlockEntry> = ebpf
        .map_mut("BLACKLIST")
        .context("BLACKLIST map not found")?
        .try_into()?;

    let mut entries = Vec::with_capacity(config.blacklist.len());
    for ip_str in &config.blacklist {
        let ip = parse_ip(ip_str)?;
        let entry = BlockEntry {
            blocked_until_ns: 0, // 永久封禁
            block_reason: rules::BLACKLIST as u8,
            hit_count: 0,
            first_seen_ns: 0,
        };
        blacklist.insert(ip, entry, 0)?;
        info!("loaded blacklist entry: {}", ip_str);
        entries.push(ip);
    }

    Ok(entries)
}

fn init_whitelist_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<Vec<(u32, u32)>> {
    let mut whitelist: LpmTrie<_, WhitelistKey, u8> = ebpf
        .map_mut("WHITELIST")
        .context("WHITELIST map not found")?
        .try_into()?;

    let mut entries = Vec::with_capacity(config.whitelist.len());
    for cidr in &config.whitelist {
        let (addr, prefix) = parse_cidr(cidr)?;
        whitelist.insert(&LpmKey::new(prefix, WhitelistKey { addr }), 1, 0)?;
        info!("loaded whitelist entry: {}", cidr);
        entries.push((addr, prefix));
    }

    Ok(entries)
}

fn parse_cidr(s: &str) -> anyhow::Result<(u32, u32)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid CIDR: {}", s);
    }
    let addr: IpAddr = parts[0].parse().context("invalid IP address")?;
    let prefix: u32 = parts[1].parse().context("invalid prefix length")?;
    if prefix > 32 {
        anyhow::bail!("invalid prefix length: {}", prefix);
    }

    match addr {
        IpAddr::V4(v4) => {
            let addr = u32::from_be_bytes(v4.octets());
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            Ok((addr & mask, prefix))
        }
        IpAddr::V6(_) => anyhow::bail!("IPv6 is not supported yet"),
    }
}

async fn reload_config(
    ebpf: &mut Ebpf,
    config_path: &str,
    current_whitelist: &mut Vec<(u32, u32)>,
    static_blacklist: &mut Vec<u32>,
) -> anyhow::Result<()> {
    let new_config = Config::from_file(config_path)?;

    init_config_map(ebpf, &new_config)?;
    init_rate_limit_map(ebpf, &new_config)?;
    init_l7_patterns_map(ebpf, &new_config)?;
    apply_whitelist_map(ebpf, &new_config, current_whitelist)?;
    apply_blacklist_map(ebpf, &new_config, static_blacklist)?;

    Ok(())
}

fn apply_whitelist_map(
    ebpf: &mut Ebpf,
    config: &Config,
    current: &mut Vec<(u32, u32)>,
) -> anyhow::Result<()> {
    let mut whitelist: LpmTrie<_, WhitelistKey, u8> = ebpf
        .map_mut("WHITELIST")
        .context("WHITELIST map not found")?
        .try_into()?;

    let new: HashSet<(u32, u32)> = config
        .whitelist
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .collect();

    // 移除已不在新配置中的条目
    for key in current.iter().copied() {
        if !new.contains(&key) {
            whitelist.remove(&LpmKey::new(key.1, WhitelistKey { addr: key.0 }))?;
            info!("removed whitelist entry: {}/{}", format_addr(key.0), key.1);
        }
    }

    // 新增条目
    for (addr, prefix) in &new {
        if !current.contains(&(*addr, *prefix)) {
            whitelist.insert(&LpmKey::new(*prefix, WhitelistKey { addr: *addr }), 1, 0)?;
            info!("added whitelist entry: {}/{}", format_addr(*addr), prefix);
        }
    }

    current.clear();
    current.extend(new);
    Ok(())
}

fn apply_blacklist_map(
    ebpf: &mut Ebpf,
    config: &Config,
    current: &mut Vec<u32>,
) -> anyhow::Result<()> {
    let mut blacklist: LruHashMap<_, u32, BlockEntry> = ebpf
        .map_mut("BLACKLIST")
        .context("BLACKLIST map not found")?
        .try_into()?;

    let new: HashSet<u32> = config
        .blacklist
        .iter()
        .map(|s| parse_ip(s))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .collect();

    // 移除已不在新配置中的静态黑名单条目（保留动态加入的条目）
    for ip in current.iter().copied() {
        if !new.contains(&ip) {
            // 仅删除由配置文件加入的静态黑名单（reason == BLACKLIST）
            let entry = blacklist.get(&ip, 0)?;
            if entry.block_reason == rules::BLACKLIST as u8 {
                blacklist.remove(&ip)?;
                info!("removed static blacklist entry: {}", format_addr(ip));
            }
        }
    }

    // 新增静态黑名单条目
    for ip in &new {
        if !current.contains(ip) {
            let entry = BlockEntry {
                blocked_until_ns: 0,
                block_reason: rules::BLACKLIST as u8,
                hit_count: 0,
                first_seen_ns: 0,
            };
            blacklist.insert(*ip, entry, 0)?;
            info!("added static blacklist entry: {}", format_addr(*ip));
        }
    }

    current.clear();
    current.extend(new);
    Ok(())
}

fn init_cookie_secrets(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut secrets: Array<_, CookieSecret> = ebpf
        .map_mut("COOKIE_SECRETS")
        .context("COOKIE_SECRETS map not found")?
        .try_into()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    secrets.set(
        0,
        CookieSecret {
            current: random_bytes(),
            previous: random_bytes(),
            bucket_index: now / 60,
        },
        0,
    )?;
    Ok(())
}

async fn rotate_cookie_secrets(ebpf: Arc<tokio::sync::Mutex<Ebpf>>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let mut guard = ebpf.lock().await;
        if let Err(e) = rotate_cookie_secrets_inner(&mut guard).await {
            warn!("cookie secret rotation failed: {}", e);
        }
    }
}

async fn rotate_cookie_secrets_inner(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut secrets_map: Array<_, CookieSecret> = ebpf
        .map_mut("COOKIE_SECRETS")
        .context("COOKIE_SECRETS map not found")?
        .try_into()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bucket = now / 60;

    let mut current = secrets_map.get(&0, 0).unwrap_or(CookieSecret {
        current: [0; 16],
        previous: [0; 16],
        bucket_index: bucket,
    });

    if bucket <= current.bucket_index {
        return Ok(());
    }

    current.previous = current.current;
    current.current = random_bytes();
    current.bucket_index = bucket;

    secrets_map.set(0, current, 0)?;
    info!("rotated SYN Cookie secret to bucket {}", bucket);
    Ok(())
}

fn random_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

fn format_addr(addr: u32) -> String {
    Ipv4Addr::from(addr.to_be_bytes()).to_string()
}
