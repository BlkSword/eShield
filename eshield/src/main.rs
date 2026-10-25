mod adaptive;
mod alert;
mod audit;
mod auth;
mod blacklist_sync;
mod config;
mod control;
mod danger;
mod event_consumer;
mod geoip;
mod health;
mod hub_client;
mod ip;
mod logging;
mod login_limiter;
mod packet_log;
mod state;
mod store;
mod threat_intel;
mod time;
mod timeseries;
mod tui;
mod web;

use anyhow::Context;
use aya::{include_bytes_aligned, maps::HashMap as LruHashMap, programs::Xdp, Ebpf};
use aya_log::EbpfLogger;
use clap::{Parser, Subcommand};
use eshield_common::{GlobalStats, IpKey};
use rand::Rng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tracing::{info, warn};

use crate::{
    alert::{AlertConfig, AlertManager},
    audit::{AuditAction, Auditor, FileAuditBackend, MemoryAuditBackend},
    auth::AuthState,
    config::Config,
    control::ControlState,
    state::AppStateInner,
    store::RuleStore,
    timeseries::MetricPoint,
};

const DEFAULT_ENDPOINT: &str = "http://localhost:8720";

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
        /// API Token（远程访问必填；也可用 ESHIELD_API_TOKEN 环境变量）
        #[arg(long)]
        token: Option<String>,
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
        /// API Token（远程访问必填；也可用 ESHIELD_API_TOKEN 环境变量）
        #[arg(long)]
        token: Option<String>,
    },
    /// 实时解封某个 IP
    Unblock {
        /// 要解封的 IPv4 地址
        ip: String,
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
        /// API Token（远程访问必填；也可用 ESHIELD_API_TOKEN 环境变量）
        #[arg(long)]
        token: Option<String>,
    },
    /// 重新加载配置文件
    Reload {
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
        /// API Token（远程访问必填；也可用 ESHIELD_API_TOKEN 环境变量）
        #[arg(long)]
        token: Option<String>,
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
        /// API Token（远程访问必填；也可用 ESHIELD_API_TOKEN 环境变量）
        #[arg(long)]
        token: Option<String>,
    },
    /// 重置控制台访问令牌
    ResetToken {
        /// eShield HTTP API 端点
        #[arg(short, long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
        /// API Token（远程访问必填；也可用 ESHIELD_API_TOKEN 环境变量）
        #[arg(long)]
        token: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => start(&config).await,
        Commands::Status { endpoint, token } => {
            show_status(&endpoint, resolve_token(token).as_deref()).await
        }
        Commands::Block {
            ip,
            duration,
            endpoint,
            token,
        } => send_block(&endpoint, &ip, duration, resolve_token(token).as_deref()).await,
        Commands::Unblock {
            ip,
            endpoint,
            token,
        } => send_unblock(&endpoint, &ip, resolve_token(token).as_deref()).await,
        Commands::Reload { endpoint, token } => {
            send_reload(&endpoint, resolve_token(token).as_deref()).await
        }
        Commands::Check { config } => check_config(&config).await,
        Commands::Tui { endpoint, token } => tui::run(endpoint, resolve_token(token)).await,
        Commands::ResetToken { endpoint, token } => {
            send_reset_token(&endpoint, resolve_token(token).as_deref()).await
        }
    }
}

/// CLI 显式 --token 优先，其次读取 ESHIELD_API_TOKEN 环境变量。
fn resolve_token(token: Option<String>) -> Option<String> {
    token.filter(|t| !t.is_empty()).or_else(|| {
        std::env::var("ESHIELD_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
    })
}

/// 构造带 Bearer Token 的 reqwest Client（无 token 时退化为普通 client）。
fn api_client(token: Option<&str>) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = token.filter(|t| !t.is_empty()) {
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token)) {
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
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

    // map 的静态元信息（name/type/max_entries）在程序生命周期内不变，
    // 启动时采集一次交给 /metrics 使用，避免每次抓取都要抢全局 Ebpf 锁。
    let map_infos = Arc::new(web::collect_map_infos(&ebpf));

    // 用户态统计状态需要在 XDP 挂载前创建，这样 program_start_ns 才能过滤掉
    // 任何在 ring buffer 中残留的 stale 事件。
    let state = Arc::new(AppStateInner::new());
    let adaptive = Arc::new(adaptive::AdaptiveEngine::new(config.adaptive.clone()));
    let packet_log = Arc::new(packet_log::PacketLog::new(
        config.packet_log.memory_max_entries,
    ));
    state
        .stats
        .program_start_ns
        .store(crate::time::monotonic_ns(), Ordering::Relaxed);

    if config.ebpf_log_enabled {
        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            warn!("failed to initialize eBPF logger: {}", e);
        } else {
            info!("eBPF logger initialized");
        }
    }

    // 初始化 SYN Cookie 密钥
    init_cookie_secrets(&mut ebpf)?;

    // 在 XDP 挂载前清空 Ring Buffer：挂载后数据面会立即开始收包并产生事件，
    // 若先挂载再 drain，可能把启动瞬间的流量事件误判为残留事件。
    //
    // RingBuf 句柄必须全生命周期持有同一个：aya 的 RingBuf 会缓存 producer 位置
    // （pos_cache 初值 0），若每批事件都重建句柄，consumer 位置会越过 producer，
    // 已消费的事件将被无限重读（表现为空流量下 4096 条/批的幻影事件 + CPU 占满）。
    // 因此这里 take_map 取出所有权，句柄随任务常驻。
    let events_ring = {
        let map = ebpf.take_map("EVENTS").expect("EVENTS map not found");
        match aya::maps::RingBuf::try_from(map) {
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
                Some(ring_buf)
            }
            Err(e) => {
                warn!("failed to open EVENTS map for drain: {}", e);
                None
            }
        }
    };

    let samples_ring = match ebpf.take_map("PACKET_SAMPLES") {
        Some(map) => match aya::maps::RingBuf::try_from(map) {
            Ok(ring_buf) => Some(ring_buf),
            Err(e) => {
                warn!("failed to open PACKET_SAMPLES ring buffer: {}", e);
                None
            }
        },
        None => {
            warn!("PACKET_SAMPLES map not found");
            None
        }
    };

    let program: &mut Xdp = ebpf
        .program_mut("eshield")
        .context("program 'eshield' not found")?
        .try_into()?;
    program.load()?;

    // XDP 挂载策略（[xdp]）：
    //   auto    —— 先 native，失败回退 generic（默认）
    //   native  —— 只允许 native，失败直接报错退出（避免"以为在跑 native、其实跑 SKB"）
    //   generic —— 强制 SKB（veth/虚拟网卡或驱动不支持 native）
    // 兼容旧环境变量 ESHIELD_XDP_MODE=skb|generic|native，优先级高于配置文件。
    let env_mode = std::env::var("ESHIELD_XDP_MODE")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let want_mode = match env_mode.as_str() {
        "skb" | "generic" => "generic".to_string(),
        "native" | "drv" => "native".to_string(),
        _ => config.xdp.mode.to_ascii_lowercase(),
    };
    let (attached_mode, link_id) = if want_mode == "generic" {
        info!(
            "[xdp].mode/ESHIELD_XDP_MODE=generic, attaching SKB on {}",
            config.interface
        );
        let id = program
            .attach(&config.interface, aya::programs::XdpFlags::SKB_MODE)
            .with_context(|| format!("failed to attach XDP program on {}", config.interface))?;
        ("generic", id)
    } else {
        let native = {
            let mut attempt =
                || program.attach(&config.interface, aya::programs::XdpFlags::DRV_MODE);
            attach_native_prefer(&mut attempt, &config.interface, config.xdp.disable_offloads)
        };
        match native {
            Ok(id) => ("native", id),
            Err(last_err) => {
                let hint = native_attach_hint(&config.interface);
                if want_mode == "native" {
                    anyhow::bail!(
                        "native XDP attach failed on {}: {last_err}；{hint}",
                        config.interface
                    );
                }
                warn!(
                    "native XDP attach failed ({last_err}), falling back to generic mode; {hint}"
                );
                let id = program
                    .attach(&config.interface, aya::programs::XdpFlags::SKB_MODE)
                    .with_context(|| {
                        format!("failed to attach XDP program on {}", config.interface)
                    })?;
                ("generic", id)
            }
        }
    };
    state.stats.xdp_attached.store(true, Ordering::Relaxed);
    state.stats.xdp_mode.store(
        if attached_mode == "native" { 1 } else { 2 },
        Ordering::Relaxed,
    );
    info!(
        "attached XDP in {} mode on {} (requested: {})",
        attached_mode, config.interface, want_mode
    );
    let xdp_link_id = Some(link_id);

    // Ebpf 状态由控制面、事件消费任务与热加载共享
    let ebpf = Arc::new(tokio::sync::Mutex::new(ebpf));

    // XDP 挂载巡检：程序被驱动重置/外部摘掉时，/ready 立刻降级并自动重挂，
    // 避免"控制台显示运行中、实际已经裸奔"。
    {
        let iface = config.interface.clone();
        let stats = state.stats.clone();
        let ebpf = ebpf.clone();
        let auto_reattach = config.xdp.auto_reattach;
        tokio::spawn(async move {
            monitor_xdp(iface, stats, ebpf, auto_reattach).await;
        });
    }

    // 可观测性组件：审计后端根据配置选择内存或文件持久化。
    let auditor = if config.audit.enabled {
        match FileAuditBackend::new(&config.audit.path, config.audit.max_size_mb) {
            Ok(backend) => {
                info!("using persistent audit log: {}", config.audit.path);
                Auditor::new(backend)
            }
            Err(e) => {
                warn!(
                    "failed to initialize file audit backend ({}), falling back to memory",
                    e
                );
                Auditor::new(MemoryAuditBackend::new(10_000))
            }
        }
    } else {
        Auditor::new(MemoryAuditBackend::new(10_000))
    };
    let store = RuleStore::new(&config.store_path).context("failed to open rule store")?;

    // 从 redb 恢复近期时序指标，使 Dashboard 趋势图在重启后保持连续。
    // 过滤掉大于当前单调时钟的点（通常来自上一次系统启动），避免跨重启的时间异常。
    let now = crate::time::monotonic_secs();
    let retention_s = config.timeseries_retention_days.saturating_mul(86400);
    let since = now.saturating_sub(retention_s);
    match store.load_timeseries(since).await {
        Ok(points) => {
            let points: Vec<MetricPoint> =
                points.into_iter().filter(|p| p.timestamp <= now).collect();
            let count = points.len();
            let mut window = state.stats.timeseries.write().await;
            window.load(points);
            info!("loaded {} timeseries points from store", count);
        }
        Err(e) => warn!("failed to load persisted timeseries: {}", e),
    }
    // 记录已经落盘的最后一个时间点，后续只增量写入新点，避免每 60s 全量重写 redb。
    let last_persisted_ts = Arc::new(AtomicU64::new({
        let guard = state.stats.timeseries.read().await;
        guard.last_timestamp()
    }));

    let alert = AlertManager::new(AlertConfig {
        webhook_url: config.alert_webhook_url.clone(),
        webhook_type: config.alert_webhook_type.clone(),
        threshold_dps: config.alert_threshold_dps,
        cooldown_s: config.alert_cooldown_s,
        interface: config.interface.clone(),
    });
    // 若未配置 api_token，则自动生成随机 Token。
    // 为降低日志泄露风险，仅输出 token 前缀；完整 Token 可用本机
    // `eshield reset-token`（自动生成并打印新 Token）获取。
    let api_token = config
        .api_token
        .clone()
        .filter(|t| !t.is_empty())
        .or_else(|| {
            let token = format!("{:032x}", rand::random::<u128>());
            warn!(
                "api_token not configured; generated random console access token (prefix): {}...",
                &token[..8]
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
    // 控制台默认是明文 HTTP + Bearer Token/Cookie；token 一旦被嗅探即可完全接管。
    // 非环回监听且未显式声明"已在 TLS 反代之后"时给出显著告警（不阻断启动）。
    if !bind_is_loopback(&web_bind) && std::env::var("ESHIELD_ASSUME_TLS_PROXY").is_err() {
        warn!(
            "控制台以**明文 HTTP** 监听在 {web_bind}：请置于 nginx/Caddy 等 TLS 反向代理之后，\
             否则控制台口令与 API Token 会在网络上明文传输。\
             若已由反代终结 TLS，可设置 ESHIELD_ASSUME_TLS_PROXY=1 关闭本告警。"
        );
    }

    let _web_handle = {
        let stats = state.stats.clone();
        let control = control.clone();
        let auditor = auditor.clone();
        let packet_log = packet_log.clone();
        let map_infos = map_infos.clone();
        tokio::spawn(async move {
            if let Err(e) = web::run(
                stats, control, auditor, auth, web_bind, packet_log, map_infos,
            )
            .await
            {
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
                let total = stats
                    .total_dropped
                    .load(std::sync::atomic::Ordering::Relaxed);
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
            threat_intel::ThreatIntelSync::new(control)
                .run(ti_config)
                .await;
        })
    };

    // 启动 Hub 分布式同步任务（若启用）
    let hub_client_handle = {
        let control = control.clone();
        let hub_config = config.hub.clone();
        tokio::spawn(async move {
            if hub_config.enabled {
                match hub_client::HubClient::new(hub_config, control) {
                    Ok(client) => client.run().await,
                    Err(e) => tracing::warn!("failed to initialize hub client: {}", e),
                }
            }
        })
    };

    // 启动 BLACKLIST map → store 后台同步，使数据面检测产生的动态黑名单可被 Hub 上报
    let _blacklist_sync_handle = {
        let ebpf = ebpf.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let syncer = blacklist_sync::BlacklistSync::new(ebpf, store, Duration::from_secs(5));
            syncer.run().await;
        })
    };

    // 启动自适应引擎清理任务：周期清理过期窗口/封禁，并限制 DashMap 上限，防止内存无界增长。
    let adaptive_prune_handle = {
        let adaptive = adaptive.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                adaptive.prune(crate::time::monotonic_secs());
            }
        })
    };

    // 启动事件消费任务：RingBuf 句柄常驻（见上方说明），Ebpf 锁仅用于自适应引擎写 map
    let event_handle = {
        let stats = state.stats.clone();
        let adaptive = adaptive.clone();
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            let Some(mut ring_buf) = events_ring else {
                warn!("EVENTS ring buffer unavailable, event consumer not started");
                return;
            };
            loop {
                let mut guard = ebpf.lock().await;
                match event_consumer::run(
                    stats.clone(),
                    adaptive.clone(),
                    &mut ring_buf,
                    &mut guard,
                )
                .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("event consumer exited: {}", e);
                        break;
                    }
                }
                // 尽快释放 eBPF 锁，避免阻塞同步 / Web 任务。
                drop(guard);
                // 每批事件处理后让出 1ms，避免单核占满并给 Web / 控制面留响应时间
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };

    // 启动采样包日志消费任务：RingBuf 句柄常驻（见上方说明），不再需要 Ebpf 锁
    let packet_log_handle = {
        let packet_log = packet_log.clone();
        tokio::spawn(async move {
            let Some(mut ring_buf) = samples_ring else {
                warn!("PACKET_SAMPLES ring buffer unavailable, packet log consumer not started");
                return;
            };
            loop {
                match packet_log::run(packet_log.clone(), &mut ring_buf).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("packet log consumer exited: {}", e);
                        break;
                    }
                }
                // 10ms 轮询一次；包日志是采样诊断功能，不需要亚毫秒级延迟。
                tokio::time::sleep(Duration::from_millis(10)).await;
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

    // 启动 TOP 攻击源同步任务：每秒从 eBPF TOP_ATTACKERS map 读取热榜数据
    let top_attackers_handle = {
        let stats = state.stats.clone();
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            sync_top_attackers(ebpf, stats).await;
        })
    };

    // 启动 Trust Score 同步任务：低频读取信誉数据（try_lock，抢不到就跳过）
    let trust_sync_handle = {
        let stats = state.stats.clone();
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            sync_trust_scores(ebpf, stats).await;
        })
    };

    // 启动 eBPF map 条目数采样任务：/metrics 只读缓存值，不在抓取路径遍历大表
    let map_entries_interval_s = config.metrics_interval_s;
    let _map_entries_handle = {
        let stats = state.stats.clone();
        let ebpf = ebpf.clone();
        tokio::spawn(async move {
            sync_map_entries(ebpf, stats, map_entries_interval_s).await;
        })
    };

    // 启动 Danger Signal 监测任务：按配置周期采样并更新全局危险等级
    let danger_handle = {
        let stats = state.stats.clone();
        let control = control.clone();
        let danger_cfg = config.danger_signal.clone();
        tokio::spawn(async move {
            if danger_cfg.enabled {
                let monitor =
                    std::sync::Arc::new(danger::DangerMonitor::new(danger_cfg.anomaly_multiplier));
                let mut tick =
                    tokio::time::interval(Duration::from_secs(danger_cfg.sample_interval_s));
                loop {
                    tick.tick().await;
                    let dps = stats.current_dps.load(Ordering::Relaxed);
                    // 必须先读旧等级再采样；sample 只返回新等级，不再自己写 level。
                    let prev = monitor.level.load(Ordering::Relaxed);
                    let level = monitor.sample(dps);
                    if level != prev {
                        monitor.level.store(level, Ordering::Relaxed);
                        if let Err(e) = control.set_danger_level(level).await {
                            warn!("failed to apply danger level to eBPF: {}", e);
                        }
                        stats.danger_level.store(level as u64, Ordering::Relaxed);
                        info!("danger level changed: {} -> {} (dps={})", prev, level, dps);
                    }
                }
            }
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

    // 启动时序指标持久化任务：每 60 秒增量写入 redb，并清理超过保留期的数据
    let timeseries_persist_handle = {
        let stats = state.stats.clone();
        let store = store.clone();
        let retention_days = config.timeseries_retention_days;
        let last_persisted_ts = last_persisted_ts.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let from_ts = last_persisted_ts.load(Ordering::Relaxed);
                let points = {
                    let ts = stats.timeseries.clone();
                    let guard = ts.read().await;
                    guard.snapshot_after(from_ts)
                };
                if let Some(last) = points.last() {
                    if let Err(e) = store.save_timeseries(&points).await {
                        warn!("failed to persist timeseries: {}", e);
                    } else {
                        last_persisted_ts.store(last.timestamp, Ordering::Relaxed);
                    }
                }
                let now = crate::time::monotonic_secs();
                let before = now.saturating_sub(retention_days.saturating_mul(86400));
                match store.prune_timeseries(before).await {
                    Ok(pruned) if pruned > 0 => {
                        info!("pruned {} old timeseries points", pruned);
                    }
                    Ok(_) => {}
                    Err(e) => warn!("failed to prune timeseries: {}", e),
                }
            }
        })
    };

    let mut sighup = unix_signal(SignalKind::hangup())?;
    let mut sigterm = unix_signal(SignalKind::terminate())?;

    info!(
        "eShield is running on {}, press Ctrl-C to stop, send SIGHUP to reload config",
        config.interface
    );

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("shutting down eShield (SIGINT)");
                auditor
                    .log("system", AuditAction::Stop, serde_json::json!({}), None)
                    .await;
                break;
            }
            _ = sigterm.recv() => {
                info!("shutting down eShield (SIGTERM)");
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
    packet_log_handle.abort();
    rotator_handle.abort();
    alert_handle.abort();
    threat_intel_handle.abort();
    hub_client_handle.abort();
    timeseries_handle.abort();
    timeseries_persist_handle.abort();
    global_stats_handle.abort();
    trust_sync_handle.abort();
    danger_handle.abort();
    top_attackers_handle.abort();
    adaptive_prune_handle.abort();
    let _ = trust_sync_handle.await;
    let _ = danger_handle.await;
    let _ = event_handle.await;
    let _ = packet_log_handle.await;
    let _ = rotator_handle.await;
    let _ = alert_handle.await;
    let _ = threat_intel_handle.await;
    let _ = hub_client_handle.await;
    let _ = timeseries_handle.await;
    let _ = timeseries_persist_handle.await;
    let _ = global_stats_handle.await;
    let _ = top_attackers_handle.await;
    let _ = adaptive_prune_handle.await;

    // 优雅退出前最后保存一次时序指标，避免最近 60 秒内的数据丢失。
    {
        let from_ts = last_persisted_ts.load(Ordering::Relaxed);
        let guard = state.stats.timeseries.read().await;
        let points = guard.snapshot_after(from_ts);
        drop(guard);
        if !points.is_empty() {
            if let Err(e) = store.save_timeseries(&points).await {
                warn!("failed to save timeseries on shutdown: {}", e);
            }
        }
    }

    // 优雅退出：显式卸载 XDP 程序，避免 systemd stop / SIGTERM 时留下悬空 XDP 钩子。
    if let Some(link_id) = xdp_link_id {
        let mut guard = ebpf.lock().await;
        if let Some(prog) = guard.program_mut("eshield") {
            if let Ok(xdp) = prog.try_into() as Result<&mut Xdp, _> {
                if let Err(e) = xdp.detach(link_id) {
                    warn!("failed to detach XDP program: {}", e);
                } else {
                    info!("XDP program detached gracefully");
                }
            }
        }
    }

    Ok(())
}

async fn show_status(endpoint: &str, token: Option<&str>) -> anyhow::Result<()> {
    let client = api_client(token);
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

async fn send_block(
    endpoint: &str,
    ip: &str,
    duration: u64,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = api_client(token);
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

async fn send_unblock(endpoint: &str, ip: &str, token: Option<&str>) -> anyhow::Result<()> {
    let client = api_client(token);
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

async fn send_reload(endpoint: &str, token: Option<&str>) -> anyhow::Result<()> {
    let client = api_client(token);
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

async fn send_reset_token(endpoint: &str, token: Option<&str>) -> anyhow::Result<()> {
    let client = api_client(token);
    let resp = client
        .post(format!("{}/api/auth/reset-token", endpoint))
        .send()
        .await
        .context("无法连接 eShield API")?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.context("解析 API 响应失败")?;
        if let Some(new_token) = body["token"].as_str() {
            println!(
                "访问令牌已重置：{}\n请妥善保存，旧令牌已立即失效。",
                new_token
            );
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

    // bucket 必须与 eBPF 数据面 `bpf_ktime_get_ns()` 的秒级 bucket 对齐，
    // 因此使用 CLOCK_MONOTONIC 而非 UNIX_EPOCH。
    let now = crate::time::monotonic_secs();

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

    // bucket 使用 CLOCK_MONOTONIC，与 eBPF 数据面保持一致。
    let now = crate::time::monotonic_secs();
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

/// 每 30 秒从 eBPF TRUST_MAP 读取所有 IP 的 TrustEntry，同步到用户态 Stats。
/// 降频并改用 try_lock：TRUST_MAP 最多 10 万条目，全量迭代代价高；信誉分布只是
/// 展示型指标，抢不到 Ebpf 锁时直接跳过，绝不能和事件消费/策略写入排队。
async fn sync_trust_scores(ebpf: Arc<tokio::sync::Mutex<Ebpf>>, stats: Arc<crate::state::Stats>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let Ok(mut guard) = ebpf.try_lock() else {
            tracing::debug!("sync_trust_scores skipped: ebpf lock busy");
            continue;
        };
        let mut trusted = 0u64;
        let mut neutral = 0u64;
        let mut suspicious = 0u64;
        let mut malicious = 0u64;
        match LruHashMap::<_, IpKey, eshield_common::TrustEntry>::try_from(
            guard.map_mut("TRUST_MAP").expect("TRUST_MAP map not found"),
        ) {
            Ok(trust_map) => {
                for (_key, entry) in trust_map.iter().flatten() {
                    match entry.level {
                        1 => trusted += 1,
                        2 => neutral += 1,
                        3 => suspicious += 1,
                        4 => malicious += 1,
                        _ => {}
                    }
                }
            }
            Err(e) => {
                tracing::debug!("failed to open TRUST_MAP: {}", e);
            }
        }
        drop(guard);

        stats.trust_trusted.store(trusted, Ordering::Relaxed);
        stats.trust_neutral.store(neutral, Ordering::Relaxed);
        stats.trust_suspicious.store(suspicious, Ordering::Relaxed);
        stats.trust_malicious.store(malicious, Ordering::Relaxed);
    }
}

/// 解析 `ip -j link show dev <iface>` 里的 XDP 挂载信息，返回 (程序名, mode 数值)。
/// 返回 None 表示接口未挂 XDP 或 iproute2 不可用。
fn probe_xdp(iface: &str) -> Option<(String, u32)> {
    let out = std::process::Command::new("ip")
        .args(["-j", "link", "show", "dev", iface])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let xdp = value.get(0)?.get("xdp")?;
    let name = xdp
        .get("prog")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    let mode = xdp.get("mode").and_then(|m| m.as_u64()).unwrap_or(0) as u32;
    Some((name, mode))
}

/// 尝试关闭 virtio_net 上会导致 native XDP 挂载失败的 offload，返回实际关闭成功的项。
///
/// 内核在 `virtnet_xdp_set()` 里检查：宿主机实现 GRO_HW/CSUM 时直接拒绝 native XDP。
/// 部分云主机允许 guest 关闭，部分显示 `[fixed]` 由宿主机固定开启（此时无解，只能 SKB）。
fn disable_virtio_offloads(iface: &str) -> Vec<String> {
    const FEATURES: [&str; 3] = ["rx-gro-hw", "tx-checksum-ip-generic", "tx-checksum-ipv4"];
    let mut changed = Vec::new();
    for feature in FEATURES {
        if let Ok(out) = std::process::Command::new("ethtool")
            .args(["-K", iface, feature, "off"])
            .output()
        {
            if out.status.success() {
                changed.push(feature.to_string());
            }
        }
    }
    changed
}

/// 尝试 native 挂载；失败时按需关闭 virtio_net offload 再重试一次。
///
/// 用泛型 `T`/`E` 承接 `attach()` 的返回值与错误类型，避免在本模块里写死 aya 的
/// link id / ProgramError 类型（跨 aya 版本更稳）。
fn attach_native_prefer<F, T, E>(
    attach: &mut F,
    iface: &str,
    disable_offloads: bool,
) -> Result<T, String>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Display,
{
    let first_err = match attach() {
        Ok(id) => return Ok(id),
        Err(e) => e.to_string(),
    };

    if disable_offloads {
        let changed = disable_virtio_offloads(iface);
        if !changed.is_empty() {
            info!(
                "为支持 native XDP 已关闭 {iface} 的 offload: {}",
                changed.join(", ")
            );
            return attach().map_err(|e| e.to_string());
        }
    }
    Err(first_err)
}

/// native 挂载失败时的可执行排障提示。
fn native_attach_hint(iface: &str) -> String {
    format!(
        "若网卡是 virtio_net，这是宿主机开启 GRO_HW/CSUM 导致的已知限制：\
         请检查 `ethtool -k {iface} | grep -E 'rx-gro-hw|tx-checksum'`；\
         若显示 [fixed] 表示由宿主机固定开启、guest 无法关闭，只能使用 generic 模式\
         （或改用支持 XDP 的网卡系列，如 AWS ENA / 阿里云弹性网卡 / Intel i40e/ice）。"
    )
}

/// 周期性校验 XDP 是否真的挂在内核里；被摘掉时更新状态并（可选）自动重挂。
async fn monitor_xdp(
    iface: String,
    stats: Arc<crate::state::Stats>,
    ebpf: Arc<tokio::sync::Mutex<Ebpf>>,
    auto_reattach: bool,
) {
    use aya::programs::XdpFlags;

    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.tick().await; // 首次 tick 立即返回，跳过
    loop {
        interval.tick().await;

        match probe_xdp(&iface) {
            Some((name, mode)) if name == "eshield" => {
                stats.xdp_attached.store(true, Ordering::Relaxed);
                stats
                    .xdp_mode
                    .store(if mode == 2 { 2 } else { 1 }, Ordering::Relaxed);
            }
            other => {
                let was = stats.xdp_attached.swap(false, Ordering::Relaxed);
                let desc = match &other {
                    Some((n, m)) => format!("{n}(mode {m})"),
                    None => "无 XDP 程序".to_string(),
                };
                if was {
                    tracing::error!("检测到 XDP 程序已不在 {iface} 上（当前: {desc}），防护已失效");
                }
                if !auto_reattach {
                    continue;
                }
                let Ok(mut guard) = ebpf.try_lock() else {
                    continue;
                };
                let Some(prog) = guard.program_mut("eshield") else {
                    continue;
                };
                if let Ok(xdp) = prog.try_into() as Result<&mut Xdp, _> {
                    let native = {
                        let mut attempt = || xdp.attach(&iface, XdpFlags::DRV_MODE);
                        attach_native_prefer(&mut attempt, &iface, true)
                    };
                    let attached_mode: Option<&'static str> = match native {
                        Ok(_id) => Some("native"),
                        Err(e) => {
                            warn!("native 重挂失败（{e}），回退 generic 模式");
                            match xdp.attach(&iface, XdpFlags::SKB_MODE) {
                                Ok(_id) => Some("generic"),
                                Err(e2) => {
                                    tracing::error!("XDP 自动重挂失败: {e2}");
                                    None
                                }
                            }
                        }
                    };
                    if let Some(mode) = attached_mode {
                        stats.xdp_attached.store(true, Ordering::Relaxed);
                        stats
                            .xdp_mode
                            .store(if mode == "native" { 1 } else { 2 }, Ordering::Relaxed);
                        tracing::info!("XDP 已在 {iface} 上自动重新挂载（{mode}）");
                    }
                }
            }
        }
    }
}

/// 判断 Web 监听地址是否仅绑定环回（环回上明文 HTTP 风险可接受）。
fn bind_is_loopback(bind: &str) -> bool {
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    host == "localhost" || host.starts_with("127.") || host == "[::1]" || host == "::1"
}

/// 周期采样 eBPF 各 LRU map 的当前条目数，缓存到 Stats.map_entries。
///
/// `/metrics` 每次被抓取都要输出 map 使用量；若在请求处理时直接遍历可能各含
/// 10 万条目的 LRU Hash，会长时间持有全局 Ebpf 锁并阻塞事件消费。因此把遍历
/// 挪到后台低频任务（`metrics_interval_s` 可配），抓取路径只读缓存。
async fn sync_map_entries(
    ebpf: Arc<tokio::sync::Mutex<Ebpf>>,
    stats: Arc<crate::state::Stats>,
    interval_s: u64,
) {
    use eshield_common::{
        BlockEntry, ConnTrackEntry, PortRateKey, ProjectPolicy, ProjectPolicyKey, RateCounter,
        TrustEntry,
    };
    const CAP: usize = 20_000;

    let mut interval = tokio::time::interval(Duration::from_secs(interval_s.max(5)));
    loop {
        interval.tick().await;
        let Ok(mut guard) = ebpf.try_lock() else {
            tracing::debug!("sync_map_entries skipped: ebpf lock busy");
            continue;
        };

        let mut sampled: Vec<(&'static str, u64)> = Vec::new();

        // 每张表的 key/value 类型不同，逐个分支统计；CAP 限制单表遍历成本。
        if let Some(map) = guard.map_mut("BLACKLIST") {
            if let Ok(m) = LruHashMap::<_, IpKey, BlockEntry>::try_from(map) {
                sampled.push(("BLACKLIST", m.iter().take(CAP).count() as u64));
            }
        }
        if let Some(map) = guard.map_mut("RATE_MAP") {
            if let Ok(m) = LruHashMap::<_, IpKey, RateCounter>::try_from(map) {
                sampled.push(("RATE_MAP", m.iter().take(CAP).count() as u64));
            }
        }
        if let Some(map) = guard.map_mut("PORT_RATE_MAP") {
            if let Ok(m) = LruHashMap::<_, PortRateKey, RateCounter>::try_from(map) {
                sampled.push(("PORT_RATE_MAP", m.iter().take(CAP).count() as u64));
            }
        }
        if let Some(map) = guard.map_mut("TRUST_MAP") {
            if let Ok(m) = LruHashMap::<_, IpKey, TrustEntry>::try_from(map) {
                sampled.push(("TRUST_MAP", m.iter().take(CAP).count() as u64));
            }
        }
        if let Some(map) = guard.map_mut("CONN_TRACK") {
            if let Ok(m) = LruHashMap::<_, IpKey, ConnTrackEntry>::try_from(map) {
                sampled.push(("CONN_TRACK", m.iter().take(CAP).count() as u64));
            }
        }
        if let Some(map) = guard.map_mut("SYN_PROXY_CONN") {
            if let Ok(m) = LruHashMap::<_, IpKey, u64>::try_from(map) {
                sampled.push(("SYN_PROXY_CONN", m.iter().take(CAP).count() as u64));
            }
        }
        if let Some(map) = guard.map_mut("TOP_ATTACKERS") {
            if let Ok(m) = LruHashMap::<_, IpKey, u64>::try_from(map) {
                sampled.push(("TOP_ATTACKERS", m.iter().take(CAP).count() as u64));
            }
        }
        if let Some(map) = guard.map_mut("PROJECT_POLICY") {
            if let Ok(m) = LruHashMap::<_, ProjectPolicyKey, ProjectPolicy>::try_from(map) {
                sampled.push(("PROJECT_POLICY", m.iter().take(CAP).count() as u64));
            }
        }
        drop(guard);

        for (name, count) in sampled {
            stats.map_entries.insert(name, count);
        }
        stats
            .map_entries_updated_ns
            .store(crate::time::monotonic_ns(), Ordering::Relaxed);
    }
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
            guard
                .map_mut("GLOBAL_STATS")
                .expect("GLOBAL_STATS map not found"),
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
                        acc.conn_track_blocked += v.conn_track_blocked;
                        acc.blacklist_blocked += v.blacklist_blocked;
                        acc.tcp_rst_sent += v.tcp_rst_sent;
                        acc.tcp_rst_fail += v.tcp_rst_fail;
                        acc.tcp_rst_attempt += v.tcp_rst_attempt;
                        acc.tcp_dropped += v.tcp_dropped;
                        acc.udp_dropped += v.udp_dropped;
                        acc.icmp_dropped += v.icmp_dropped;
                        acc.other_dropped += v.other_dropped;
                    }
                    tracing::debug!(
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

        stats
            .total_packets
            .store(acc.total_packets, Ordering::Relaxed);
        stats
            .total_dropped
            .store(acc.total_dropped, Ordering::Relaxed);
        stats
            .total_passed
            .store(acc.total_passed, Ordering::Relaxed);
        stats
            .syn_flood_blocked
            .store(acc.syn_flood_blocked, Ordering::Relaxed);
        stats
            .rate_limited
            .store(acc.rate_limited, Ordering::Relaxed);
        stats.l7_blocked.store(acc.l7_blocked, Ordering::Relaxed);
        stats
            .udp_flood_blocked
            .store(acc.udp_flood_blocked, Ordering::Relaxed);
        stats
            .icmp_flood_blocked
            .store(acc.icmp_flood_blocked, Ordering::Relaxed);
        stats
            .geoip_blocked
            .store(acc.geoip_blocked, Ordering::Relaxed);
        stats
            .conn_track_blocked
            .store(acc.conn_track_blocked, Ordering::Relaxed);
        stats
            .blacklist_blocked
            .store(acc.blacklist_blocked, Ordering::Relaxed);
        stats
            .tcp_rst_sent
            .store(acc.tcp_rst_sent, Ordering::Relaxed);
        stats
            .tcp_rst_fail
            .store(acc.tcp_rst_fail, Ordering::Relaxed);
        stats
            .tcp_rst_attempt
            .store(acc.tcp_rst_attempt, Ordering::Relaxed);
        stats.tcp_dropped.store(acc.tcp_dropped, Ordering::Relaxed);
        stats.udp_dropped.store(acc.udp_dropped, Ordering::Relaxed);
        stats
            .icmp_dropped
            .store(acc.icmp_dropped, Ordering::Relaxed);
        stats
            .other_dropped
            .store(acc.other_dropped, Ordering::Relaxed);

        let pps = acc.total_packets.saturating_sub(last_packets);
        let dps = acc.total_dropped.saturating_sub(last_dropped);
        stats.current_pps.store(pps, Ordering::Relaxed);
        stats.current_dps.store(dps, Ordering::Relaxed);
        last_packets = acc.total_packets;
        last_dropped = acc.total_dropped;
    }
}

/// 每秒从 eBPF TOP_ATTACKERS map 读取高频攻击源热榜，重建用户态 top_attackers。
///
/// TOP_ATTACKERS 由数据面在命中 BLACKLIST 时直接维护：只保留最近/最活跃的攻击源，
/// 容量固定（256 条）。用户态无需每秒全量扫描 BLACKLIST（可能达十万条），
/// 显著降低控制面 CPU 和锁占用，同时保证 Dashboard/告警展示 Top-20 的来源准确性。
async fn sync_top_attackers(ebpf: Arc<tokio::sync::Mutex<Ebpf>>, stats: Arc<crate::state::Stats>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let mut guard = ebpf.lock().await;
        let mut next: HashMap<IpKey, u64> = HashMap::new();
        match LruHashMap::<_, IpKey, u64>::try_from(
            guard
                .map_mut("TOP_ATTACKERS")
                .expect("TOP_ATTACKERS map not found"),
        ) {
            Ok(top) => {
                for res in top.iter() {
                    match res {
                        Ok((key, count)) => {
                            if count > 0 {
                                next.insert(key, count);
                            }
                        }
                        Err(e) => warn!("failed to read TOP_ATTACKERS entry: {}", e),
                    }
                }
            }
            Err(e) => {
                warn!("failed to open TOP_ATTACKERS map: {}", e);
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

#[cfg(test)]
mod tests {
    use super::bind_is_loopback;

    #[test]
    fn test_bind_is_loopback() {
        for ok in [
            "127.0.0.1:8720",
            "127.0.0.1",
            "localhost:8720",
            "[::1]:8720",
            "::1",
        ] {
            assert!(bind_is_loopback(ok), "{ok} 应判定为环回");
        }
        for not_ok in [
            "0.0.0.0:8720",
            "172.23.83.38:8720",
            "[::]:8720",
            "example.com:80",
        ] {
            assert!(!bind_is_loopback(not_ok), "{not_ok} 不应判定为环回");
        }
    }
}
