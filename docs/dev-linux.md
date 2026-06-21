> .

## 推荐的 Linux 开发环境

### 选项 1：Ubuntu 22.04 云主机 / 虚拟机

```bash
# 安装依赖
sudo apt update
sudo apt install -y build-essential llvm clang libelf1 linux-headers-$(uname -r) pkg-config

# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 安装工具链
rustup toolchain install nightly
rustup target add bpfel-unknown-none --toolchain nightly
rustup component add rust-src --toolchain nightly
rustup target add x86_64-unknown-linux-musl --toolchain stable

# 安装 bpf-linker
cargo install bpf-linker

# 克隆并构建
git clone https://github.com/eshield/eshield.git
cd eshield
cargo xtask build
```

### 选项 2：WSL2

在 Windows 上启用 WSL2 并安装 Ubuntu 22.04，然后在 WSL2 中执行与选项 1 相同的命令。

### 选项 3：Vagrant

项目根目录提供了 `Vagrantfile`，可一键启动 Ubuntu 22.04 开发机：

```bash
vagrant up
vagrant ssh
# 然后在虚拟机中执行选项 1 的命令
cd /vagrant
cargo xtask build
```

### 选项 4：Docker

```bash
docker build -t eshield-dev -f Dockerfile.dev .
docker run --rm -it -v $(pwd):/workspace -w /workspace --privileged eshield-dev
# 在容器中
cargo xtask build
```

## 运行测试

```bash
# 单元测试
cargo test --workspace --exclude eshield-ebpf

# 集成测试（需要 root，会创建网络命名空间）
sudo cargo test --test integration_tests

# 基准测试（需要两台机器或多网卡环境）
sudo ./scripts/benchmark.sh
```
