mod adaptive;
mod alert;
mod audit;
mod auth;
mod config;
mod control;
mod event_consumer;
mod geoip;
mod health;
mod ip;
mod login_limiter;
mod logging;
mod state;
mod store;
mod threat_intel;
mod timeseries;
mod tui;
mod web;

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::HashMap as LruHashMap,
    programs::Xdp,
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::{Parser, Subcommand};
use rand::Rng;
use eshield_common::{BlockEntry, GlobalStats, IpKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tracing::{info, warn};

use crate::{
    alert::{AlertConfig, AlertManager},
    audit::{AuditAction, Auditor, MemoryAuditBackend},
    auth::AuthState,
    config::Config,
    control::ControlState,
    state::AppStateInner,
    store::RuleStore,
};

const DEFAULT_ENDPOINT: &str = "http://localhost:8443";

/// 读取 CLOCK_MONOTONIC，返回自系统启动以来的纳秒数。
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return 0;
        }
    }
    (ts.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(ts.tv_nsec as u64)
}

#[derive(Debug, Parser)]
#[command(name = "eshield")]
#[command(about = "eBPF/XDP 主机级 CC 防御盾")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// 启动 XDP 防护守护进程
    Start {
        /// 配置文件路径
        #[arg(short, long, default_value = "/etc/eshield/config.toml")]
        config: String,
    },
    /// 查看运行状态
    Status {
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
    },
    /// 实时封禁某个 IP
    Block {
        /// 要封禁的 IPv4 地址
        ip: String,
        /// 封禁时长（秒），0 表示永久
        #[arg(short, long, default_value = "0")]
        duration: u64,
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
    },
    /// 实时解封某个 IP
    Unblock {
        /// 要解封的 IPv4 地址
        ip: String,
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
    },
    /// 重新加载配置文件
    Reload {
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
    },
    /// 校验配置文件
    Check {
        /// 配置文件路径
        #[arg(short, long, default_value = "/etc/eshield/config.toml")]
        config: String,
    },
    /// 启动独立 TUI 仪表盘
    Tui {
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
    },
    /// 重置控制台访问令牌
    ResetToken {
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => start(&config).await,
        Commands::Status { endpoint } => show_status(&endpoint).await,
        Commands::Block {
            ip,
            duration,
            endpoint,
        } => send_block(&endpoint, &ip, duration).await,
        Commands::Unblock { ip, endpoint } => send_unblock(&endpoint, &ip).await,
        Commands::Reload { endpoint } => send_reload(&endpoint).await,
        Commands::Check { config } => check_config(&config).await,
        Commands::Tui { endpoint } => tui::run(endpoint).await,
        Commands::ResetToken { endpoint } => send_reset_token(&endpoint).await,
    }
}

async fn check_config(config_path: &str) -> anyhow::Result<()> {
    let config = Config::from_file(config_path).context("读取配置文件失败")?;
    config.validate().context("配置校验失败")?;
    println!("配置文件校验通过");
    Ok(())
}

async fn start(config_path: &str) -> anyhow::Result<()> {
    let config = Config::from_file(config_path).context("读取配置文件失败")?;
    config
        .validate()
        .context("配置校验失败，请检查 /etc/eshield/config.toml")?;

    logging::init_tracing(&config.log_level, config.log_json);

    info!("loading eShield eBPF program");

    // eBPF 统一使用 release 产物嵌入，避免 debug 构建因 overflow-checks panic 代码导致 bpf-linker 失败
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/eshield"
    ))?;

    if config.ebpf_log_enabled {
        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            warn!("failed to initialize eBPF logger: {}", e);
        } else {
            info!("eBPF logger initialized");
        }
    }

    // 初始化 SYN Cookie 密钥
    init_cookie_secrets(&mut ebpf)?;

    let program: &mut Xdp = ebpf
        .program_mut("eshield")
        .context("program 'eshield' not found")?
        .try_into()?;
    program.load()?;

    // 优先原生模式挂载，失败则回退到通用模式
    match program.attach(&config.interface, aya::programs::XdpFlags::DRV_MODE) {
        Ok(_) => info!("attached XDP in DRV (native) mode on {}", config.interface),
        Err(e) => {
            warn!("native XDP attach failed ({}), trying generic mode", e);
            program
                .attach(&config.interface, aya::programs::XdpFlags::SKB_MODE)
                .context("failed to attach XDP program")?;
            info!("attached XDP in SKB (generic) mode on {}", config.interface);
        }
    }

    let state = Arc::new(AppStateInner::new());
    state.stats.program_start_ns.store(monotonic_ns(), Ordering::Relaxed);
    let adaptive = Arc::new(adaptive::AdaptiveEngine::new(config.adaptive.clone()));

    // Ebpf 状态由控制面、事件消费任务与热加载共享
    let ebpf = Arc::new(tokio::sync::Mutex::new(ebpf));

    // 可观测性组件
    let auditor = Auditor::new(MemoryAuditBackend::new(10_000));
    let store = RuleStore::new(&config.store_path)
        .context("failed to open rule store")?;
    let alert = AlertManager::new(AlertConfig {
        webhook_url: config.alert_webhook_url.clone(),
        webhook_type: config.alert_webhook_type.clone(),
        threshold_dps: config.alert_threshold_dps,
        cooldown_s: config.alert_cooldown_s,
        interface: config.interface.clone(),
    });
    // 若未配置 api_token，则自动生成随机 Token 并打印到日志，避免控制台默认匿名访问。
    let api_token = config.api_token.clone().or_else(|| {
        let token = format!("{:032x}", rand::random::<u128>());
        info!(
            "api_token not configured; generated random console access token: {}",
            token
        );
        Some(token)
    });
    let auth = AuthState::new(api_token);

    // 控制面：封装所有 eBPF Map 操作，供 Web / CLI / SIGHUP 使用
    let control = Arc::new(
        ControlState::new(
            ebpf.clone(),
            config_path.to_string(),
            &config,
            Some(auditor.clone()),
            Some(store.clone()),
            Some(adaptive.clone()),
        )
        .await
        .context("failed to initialize control state")?,
    );

    // 加载之前持久化的动态规则
    if let Err(e) = control.load_persisted_rules().await {
        warn!("failed to load persisted rules: {}", e);
    }

    auditor
        .log("system", AuditAction::Start, serde_json::json!({}), None)
        .await;

    // 启动 Web 观测与控制面板
    let web_bind = config
        .web_bind
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("0.0.0.0:{}", config.web_port));
    let _web_handle = {
        let stats = state.stats.clone();
        let control = control.clone();
        let auditor = auditor.clone();
        tokio::spawn(async move {
            if let Err(e) = web::run(stats, control, auditor, auth, web_bind).await {
                warn!("web server exited: {}", e);
            }
        })
    };

    // 告警检查任务
    let alert_handle = {
        let stats = state.stats.clone();
        tokio::spawn(async move {
            let mut last_total = 0u64;
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let total = stats.total_dropped.load(std::sync::atomic::Ordering::Relaxed);
                let delta = total.saturating_sub(last_total);
                last_total = total;
                alert.check(&stats, delta, 60).await;
            }
        })
    };

    // 启动 SYN Cookie 密钥轮换任务
    let rotator_handle = {
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            rotate_cookie_secrets(ebpf).await;
        })
    };

    // 启动威胁情报同步任务
    let threat_intel_handle = {
        let control = control.clone();
        let ti_config = config.threat_intel.clone();
        tokio::spawn(async move {
            threat_intel::ThreatIntelSync::new(control).run(ti_config).await;
        })
    };

    // 启动前清空 Ring Buffer 中可能残留的 stale 事件（如前一次测试未消费完的事件），
    // 避免它们被新进程的事件消费器重复计数。
    {
        let mut guard = ebpf.lock().await;
        match aya::maps::RingBuf::try_from(
            guard.map_mut("EVENTS").expect("EVENTS map not found"),
        ) {
            Ok(mut ring_buf) => {
                let mut drained = 0usize;
                while ring_buf.next().is_some() {
                    drained += 1;
                    // 上限提高到 50M，避免旧版本遗留的巨量事件污染新进程统计
                    if drained >= 50_000_000 {
                        warn!("drained more than 50M stale events, stopping to avoid spin");
                        break;
                    }
                }
                if drained > 0 {
                    info!("drained {} stale events from EVENTS ring buffer", drained);
                }
            }
            Err(e) => warn!("failed to open EVENTS map for drain: {}", e),
        }
    }

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
                // 每批事件处理后让出 1ms，避免单核占满并给 Web / 控制面留响应时间
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };

    // 启动全局统计同步任务：每秒从 eBPF GLOBAL_STATS 同步 total_* / RST 计数 / PPS/DPS
    let global_stats_handle = {
        let stats = state.stats.clone();
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            sync_global_stats(ebpf, stats).await;
        })
    };

    // 启动 TOP 攻击源同步任务：每秒从 BLACKLIST map 读取 hit_count 重建 top_attackers
    let top_attackers_handle = {
        let stats = state.stats.clone();
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            sync_top_attackers(ebpf, stats).await;
        })
    };

    // 启动时序指标采样任务：每 10 秒记录一个数据点
    let timeseries_handle = {
        let stats = state.stats.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                let ts = stats.timeseries.clone();
                if let Ok(mut window) = ts.try_write() {
                    window.record(&stats);
                };
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
                auditor
                    .log("system", AuditAction::Stop, serde_json::json!({}), None)
                    .await;
                break;
            }
            _ = sighup.recv() => {
                info!("received SIGHUP, reloading config");
                match control.reload_config_file().await {
                    Ok(()) => info!("config reloaded successfully"),
                    Err(e) => warn!("config reload failed: {}", e),
                }
            }
        }
    }

    event_handle.abort();
    rotator_handle.abort();
    alert_handle.abort();
    threat_intel_handle.abort();
    timeseries_handle.abort();
    global_stats_handle.abort();
    top_attackers_handle.abort();
    let _ = event_handle.await;
    let _ = rotator_handle.await;
    let _ = alert_handle.await;
    let _ = threat_intel_handle.await;
    let _ = timeseries_handle.await;
    let _ = global_stats_handle.await;
    let _ = top_attackers_handle.await;

    Ok(())
}

async fn show_status(endpoint: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let stats: serde_json::Value = client
        .get(format!("{}/api/stats", endpoint))
        .send()
        .await
        .context("无法连接 eShield API，守护进程是否已启动？")?
        .json()
        .await
        .context("解析 API 响应失败")?;

    println!("eShield 运行状态");
    println!("----------------");
    println!(
        "总丢弃包数: {}",
        stats["total_dropped"].as_u64().unwrap_or(0)
    );
    println!(
        "黑名单拦截: {}",
        stats["blacklist_blocked"].as_u64().unwrap_or(0)
    );
    println!(
        "速率限制拦截: {}",
        stats["rate_limited"].as_u64().unwrap_or(0)
    );
    println!(
        "SYN Flood 拦截: {}",
        stats["syn_flood_blocked"].as_u64().unwrap_or(0)
    );
    println!("L7 指纹拦截: {}", stats["l7_blocked"].as_u64().unwrap_or(0));
    println!(
        "自适应阈值拦截: {}",
        stats["adaptive_blocked"].as_u64().unwrap_or(0)
    );
    println!(
        "UDP Flood 拦截: {}",
        stats["udp_flood_blocked"].as_u64().unwrap_or(0)
    );
    println!(
        "ICMP Flood 拦截: {}",
        stats["icmp_flood_blocked"].as_u64().unwrap_or(0)
    );

    if let Some(top) = stats["top_attackers"].as_array() {
        if !top.is_empty() {
            println!("\nTOP 攻击源:");
            for attacker in top.iter().take(10) {
                println!(
                    "  {} -> {} 包",
                    attacker["ip"].as_str().unwrap_or("?"),
                    attacker["count"].as_u64().unwrap_or(0)
                );
            }
        }
    }

    Ok(())
}

async fn send_block(endpoint: &str, ip: &str, duration: u64) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/blacklist", endpoint))
        .json(&serde_json::json!({ "ip": ip, "duration_s": duration }))
        .send()
        .await
        .context("无法连接 eShield API")?;

    if resp.status().is_success() {
        println!("已封禁 {}，时长 {} 秒", ip, duration);
    } else {
        anyhow::bail!("封禁失败: {}", resp.text().await.unwrap_or_default());
    }
    Ok(())
}

async fn send_unblock(endpoint: &str, ip: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("{}/api/blacklist", endpoint))
        .json(&serde_json::json!({ "ip": ip }))
        .send()
        .await
        .context("无法连接 eShield API")?;

    if resp.status().is_success() {
        println!("已解封 {}", ip);
    } else {
        anyhow::bail!("解封失败: {}", resp.text().await.unwrap_or_default());
    }
    Ok(())
}

async fn send_reload(endpoint: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/config/reload", endpoint))
        .send()
        .await
        .context("无法连接 eShield API")?;

    if resp.status().is_success() {
        println!("配置已重新加载");
    } else {
        anyhow::bail!("重载失败: {}", resp.text().await.unwrap_or_default());
    }
    Ok(())
}

async fn send_reset_token(endpoint: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/auth/reset-token", endpoint))
        .send()
        .await
        .context("无法连接 eShield API")?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.context("解析 API 响应失败")?;
        if let Some(new_token) = body["token"].as_str() {
            println!("访问令牌已重置：{}\n请妥善保存，旧令牌已立即失效。", new_token);
        } else {
            anyhow::bail!("响应中未包含新令牌");
        }
    } else {
        anyhow::bail!("重置令牌失败: {}", resp.text().await.unwrap_or_default());
    }
    Ok(())
}

fn init_cookie_secrets(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut secrets: aya::maps::Array<_, eshield_common::CookieSecret> = ebpf
        .map_mut("COOKIE_SECRETS")
        .context("COOKIE_SECRETS map not found")?
        .try_into()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    secrets.set(
        0,
        eshield_common::CookieSecret {
            current: random_bytes(),
            previous: random_bytes(),
            bucket_index: now / 60,
        },
        0,
    )?;
    Ok(())
}

async fn rotate_cookie_secrets(ebpf: Arc<tokio::sync::Mutex<Ebpf>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let mut guard = ebpf.lock().await;
        if let Err(e) = rotate_cookie_secrets_inner(&mut guard).await {
            warn!("cookie secret rotation failed: {}", e);
        }
    }
}

async fn rotate_cookie_secrets_inner(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut secrets_map: aya::maps::Array<_, eshield_common::CookieSecret> = ebpf
        .map_mut("COOKIE_SECRETS")
        .context("COOKIE_SECRETS map not found")?
        .try_into()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bucket = now / 60;

    let mut current = secrets_map
        .get(&0, 0)
        .unwrap_or(eshield_common::CookieSecret {
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

/// 从 eBPF GLOBAL_STATS Per-CPU 数组读取并同步到用户态 Stats。
/// 同时计算 current_pps / current_dps。
async fn sync_global_stats(ebpf: Arc<tokio::sync::Mutex<Ebpf>>, stats: Arc<crate::state::Stats>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut last_packets = 0u64;
    let mut last_dropped = 0u64;
    loop {
        interval.tick().await;
        let mut guard = ebpf.lock().await;
        let mut acc = GlobalStats::default();
        match aya::maps::PerCpuArray::<_, GlobalStats>::try_from(
            guard.map_mut("GLOBAL_STATS").expect("GLOBAL_STATS map not found"),
        ) {
            Ok(global) => match global.get(&0, 0) {
                Ok(values) => {
                    for v in values.iter() {
                        acc.total_packets += v.total_packets;
                        acc.total_dropped += v.total_dropped;
                        acc.total_passed += v.total_passed;
                        acc.syn_flood_blocked += v.syn_flood_blocked;
                        acc.rate_limited += v.rate_limited;
                        acc.l7_blocked += v.l7_blocked;
                        acc.udp_flood_blocked += v.udp_flood_blocked;
                        acc.icmp_flood_blocked += v.icmp_flood_blocked;
                        acc.geoip_blocked += v.geoip_blocked;
                        acc.blacklist_blocked += v.blacklist_blocked;
                        acc.tcp_rst_sent += v.tcp_rst_sent;
                        acc.tcp_rst_fail += v.tcp_rst_fail;
                        acc.tcp_rst_attempt += v.tcp_rst_attempt;
                    }
                    info!(
                        "sync_global_stats total_packets={} total_dropped={} blacklist_blocked={} geoip_blocked={} rst_sent={} rst_fail={} rst_attempt={}",
                        acc.total_packets, acc.total_dropped, acc.blacklist_blocked, acc.geoip_blocked,
                        acc.tcp_rst_sent, acc.tcp_rst_fail, acc.tcp_rst_attempt,
                    );
                }
                Err(e) => warn!("failed to read GLOBAL_STATS: {}", e),
            },
            Err(e) => warn!("failed to open GLOBAL_STATS map: {}", e),
        }
        drop(guard);

        stats.total_packets.store(acc.total_packets, Ordering::Relaxed);
        stats.total_dropped.store(acc.total_dropped, Ordering::Relaxed);
        stats.total_passed.store(acc.total_passed, Ordering::Relaxed);
        stats.syn_flood_blocked.store(acc.syn_flood_blocked, Ordering::Relaxed);
        stats.rate_limited.store(acc.rate_limited, Ordering::Relaxed);
        stats.l7_blocked.store(acc.l7_blocked, Ordering::Relaxed);
        stats.udp_flood_blocked.store(acc.udp_flood_blocked, Ordering::Relaxed);
        stats.icmp_flood_blocked.store(acc.icmp_flood_blocked, Ordering::Relaxed);
        stats.geoip_blocked.store(acc.geoip_blocked, Ordering::Relaxed);
        stats.blacklist_blocked.store(acc.blacklist_blocked, Ordering::Relaxed);
        stats.tcp_rst_sent.store(acc.tcp_rst_sent, Ordering::Relaxed);
        stats.tcp_rst_fail.store(acc.tcp_rst_fail, Ordering::Relaxed);
        stats.tcp_rst_attempt.store(acc.tcp_rst_attempt, Ordering::Relaxed);

        let pps = acc.total_packets.saturating_sub(last_packets);
        let dps = acc.total_dropped.saturating_sub(last_dropped);
        stats.current_pps.store(pps, Ordering::Relaxed);
        stats.current_dps.store(dps, Ordering::Relaxed);
        last_packets = acc.total_packets;
        last_dropped = acc.total_dropped;
    }
}

/// 每秒从 eBPF BLACKLIST map 读取 hit_count，重建用户态 top_attackers。
/// 高频率 DROP 路径（SYN/UDP/ICMP Flood、rate_limit、blacklist）已不再写入 RingBuf，
/// 因此不再依赖 event_consumer 聚合来源维度，避免其 backlog 导致 CPU 占满和统计不一致。
async fn sync_top_attackers(ebpf: Arc<tokio::sync::Mutex<Ebpf>>, stats: Arc<crate::state::Stats>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let mut guard = ebpf.lock().await;
        let mut next: HashMap<IpKey, u64> = HashMap::new();
        match LruHashMap::<_, IpKey, BlockEntry>::try_from(
            guard.map_mut("BLACKLIST").expect("BLACKLIST map not found"),
        ) {
            Ok(blacklist) => {
                for res in blacklist.iter() {
                    match res {
                        Ok((key, entry)) => {
                            if entry.hit_count > 0 {
                                next.insert(key, entry.hit_count as u64);
                            }
                        }
                        Err(e) => warn!("failed to read BLACKLIST entry: {}", e),
                    }
                }
            }
            Err(e) => {
                warn!("failed to open BLACKLIST map: {}", e);
                continue;
            }
        }
        drop(guard);

        stats.top_attackers.clear();
        for (key, count) in next {
            stats.top_attackers.insert(key, AtomicU64::new(count));
        }
    }
}
