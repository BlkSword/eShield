mod adaptive;
mod config;
mod control;
mod event_consumer;
mod state;
mod tui;
mod web;

use anyhow::Context;
use aya::{include_bytes_aligned, programs::Xdp, Ebpf};
use aya_log::EbpfLogger;
use clap::{Parser, Subcommand};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tracing::{info, warn};

use crate::{config::Config, control::ControlState, state::AppStateInner};

const DEFAULT_ENDPOINT: &str = "http://localhost:8443";

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
    /// 启动独立 TUI 仪表盘
    Tui {
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
    let adaptive = Arc::new(adaptive::AdaptiveEngine::new(config.adaptive.clone()));

    // Ebpf 状态由控制面、事件消费任务与热加载共享
    let ebpf = Arc::new(tokio::sync::Mutex::new(ebpf));

    // 控制面：封装所有 eBPF Map 操作，供 Web / CLI / SIGHUP 使用
    let control = Arc::new(
        ControlState::new(ebpf.clone(), config_path.to_string(), &config)
            .await
            .context("failed to initialize control state")?,
    );

    // 启动 Web 观测与控制面板
    let web_port = if config.web_port == 0 {
        8443
    } else {
        config.web_port
    };
    let _web_handle = {
        let stats = state.stats.clone();
        let control = control.clone();
        tokio::spawn(async move {
            if let Err(e) = web::run(stats, control, web_port).await {
                warn!("web server exited: {}", e);
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
                match control.reload_config_file().await {
                    Ok(()) => info!("config reloaded successfully"),
                    Err(e) => warn!("config reload failed: {}", e),
                }
            }
        }
    }

    event_handle.abort();
    rotator_handle.abort();
    let _ = event_handle.await;
    let _ = rotator_handle.await;

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
