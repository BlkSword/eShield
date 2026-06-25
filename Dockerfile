# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Builder stage: compile eBPF + userspace static binary
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl xz-utils \
       build-essential clang llvm libelf-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (stable + nightly + rust-src)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --no-modify-path
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup toolchain install nightly --component rust-src \
    && rustup target add bpfel-unknown-none --toolchain nightly \
    && rustup target add x86_64-unknown-linux-musl

# Install prebuilt bpf-linker (faster than cargo install)
RUN curl -LO https://github.com/aya-rs/bpf-linker/releases/latest/download/bpf-linker-x86_64-unknown-linux-musl.tar.gz \
    && tar -xzf bpf-linker-x86_64-unknown-linux-musl.tar.gz -C /root/.cargo/bin \
    && rm bpf-linker-x86_64-unknown-linux-musl.tar.gz

WORKDIR /build
COPY . .

RUN cargo +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release \
    && cargo build --package eshield --target x86_64-unknown-linux-musl --release

# -----------------------------------------------------------------------------
# Runtime stage: minimal distroless image
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/eshield /usr/local/bin/eshield
COPY --from=builder /build/packaging/config.example.toml /etc/eshield/config.toml

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/eshield"]
CMD ["start", "--config", "/etc/eshield/config.toml"]
