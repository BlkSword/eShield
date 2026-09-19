use anyhow::Context;
use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Debug, Parser)]
#[command(name = "cargo xtask")]
#[command(about = "Build tasks for eShield")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Build the eBPF program
    BuildEbpf {
        /// Build profile
        #[arg(short, long, default_value = "release")]
        profile: String,
    },
    /// Build userspace binary (implies build-ebpf)
    Build {
        /// Build profile
        #[arg(short, long, default_value = "release")]
        profile: String,
    },
    /// Build and run eShield start
    Run {
        /// Network interface
        #[arg(short, long, default_value = "eth0")]
        iface: String,
    },
    /// Run fmt + clippy + unit tests
    Test,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { profile } => build_ebpf(&profile),
        Commands::Build { profile } => {
            build_ebpf(&profile)?;
            build_userspace(&profile)
        }
        Commands::Run { iface } => {
            build_ebpf("release")?;
            build_userspace("release")?;
            run(&iface)
        }
        Commands::Test => run_tests(),
    }
}

fn build_ebpf(profile: &str) -> anyhow::Result<()> {
    let out_dir = match profile {
        "dev" | "debug" => "debug",
        "release" => "release",
        other => anyhow::bail!("invalid profile: {}", other),
    };

    let target = format!("target/bpfel-unknown-none/{}/eshield", out_dir);

    println!("Building eBPF program ({})...", profile);

    // 最新 nightly 的 LLVM 版本可能与 bpf-linker/内核 verifier 不兼容；
    // 默认使用已验证的 nightly-2026-07-31，可用 ESHIELD_EBPF_TOOLCHAIN 覆盖。
    let toolchain = std::env::var("ESHIELD_EBPF_TOOLCHAIN")
        .unwrap_or_else(|_| "nightly-2026-07-31".to_string());
    let mut cmd = Command::new("cargo");
    cmd.arg(format!("+{}", toolchain)).args([
        "build",
        "--package",
        "eshield-ebpf",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if profile == "release" {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to run cargo build for eBPF")?;
    anyhow::ensure!(status.success(), "eBPF build failed");

    println!("eBPF artifact: {}", target);
    Ok(())
}

fn build_userspace(profile: &str) -> anyhow::Result<()> {
    println!("Building userspace binary ({})...", profile);

    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "--package",
        "eshield",
        "--target",
        "x86_64-unknown-linux-musl",
    ]);
    if profile == "release" {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build userspace")?;
    anyhow::ensure!(status.success(), "userspace build failed");

    println!(
        "userspace artifact: target/x86_64-unknown-linux-musl/{}/eshield",
        profile
    );
    Ok(())
}

fn run(iface: &str) -> anyhow::Result<()> {
    let mut cmd = Command::new("target/x86_64-unknown-linux-musl/release/eshield");
    cmd.args(["start", "--config", "/etc/eshield/config.toml"]);
    cmd.env("ESHIELD_INTERFACE", iface);
    cmd.spawn()?.wait()?;
    Ok(())
}

fn run_tests() -> anyhow::Result<()> {
    // 用户态 crate 通过 include_bytes_aligned! 嵌入 eBPF 产物，
    // 因此 clippy/单元测试前必须先构建 release eBPF，否则干净 checkout 会编译失败。
    build_ebpf("release")?;

    println!("Running cargo fmt...");
    let status = Command::new("cargo").args(["fmt", "--check"]).status()?;
    anyhow::ensure!(status.success(), "fmt check failed");

    println!("Running cargo clippy (userspace)...");
    let status = Command::new("cargo")
        .args([
            "clippy",
            "--workspace",
            "--exclude",
            "eshield-ebpf",
            "--",
            "-D",
            "warnings",
        ])
        .status()?;
    anyhow::ensure!(status.success(), "clippy failed");

    println!("Running cargo test (userspace + hub)...");
    let status = Command::new("cargo")
        .args(["test", "--workspace", "--exclude", "eshield-ebpf"])
        .status()?;
    anyhow::ensure!(status.success(), "tests failed");

    Ok(())
}
