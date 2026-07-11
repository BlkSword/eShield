//! 时间工具函数。
//!
//! eBPF 数据面使用 `bpf_ktime_get_ns()`，对应用户态 `CLOCK_MONOTONIC`。
//! 所有写入 eBPF map 的时间戳（如黑名单 `blocked_until_ns`、`first_seen_ns`）
//! 都应使用 `monotonic_ns()`，以确保内核/用户态时间基准一致。
//!
//! 告警、审计等面向人类的时间展示可使用 `SystemTime` 获取 wall-clock 时间。

/// 返回 `CLOCK_MONOTONIC` 纳秒数，与 eBPF `bpf_ktime_get_ns()` 同源。
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return 0;
        }
    }
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

/// 返回 `CLOCK_MONOTONIC` 秒数，用于与 eBPF `bpf_ktime_get_ns()` 秒级对齐的场景。
pub fn monotonic_secs() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return 0;
        }
    }
    ts.tv_sec as u64
}
