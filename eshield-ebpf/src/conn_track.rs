//! 可选连接跟踪 / 半连接 CC 防御模块。
//!
//! 设计目标是“默认关闭、按项目位图启用、只处理 SYN/ACK/RST”：
//! - 普通数据包完全不做 map 访问；
//! - 只有 TCP SYN 递增半连接计数，ACK/RST 递减；
//! - 超过阈值时返回 true，由主流程 DROP；
//! - 窗口过期自动重置，计数归零时删除 map 条目。

use crate::maps::CONN_TRACK;
use crate::parser;
use eshield_common::pure::conn_track_step;
use eshield_common::{ConnTrackEntry, IpKey};

/// 检查并更新连接跟踪状态；返回 true 表示应 DROP。
#[inline(never)]
pub fn check_conn_track(
    src: &IpKey,
    tcp_flags: u8,
    now_ns: u64,
    threshold: u32,
    window_ms: u64,
) -> bool {
    let is_syn = parser::is_syn_flags(tcp_flags);
    let is_ack_or_rst = parser::is_ack_or_rst_flags(tcp_flags);

    // 普通数据包不触碰 CONN_TRACK，保持热路径零开销。
    if !is_syn && !is_ack_or_rst {
        return false;
    }

    let window_ns = if window_ms > u64::MAX / 1_000_000 {
        u64::MAX
    } else {
        window_ms.wrapping_mul(1_000_000)
    };

    let (half_open, last_seen_ns) = match unsafe { CONN_TRACK.get(src) } {
        Some(entry) => (entry.half_open, entry.last_seen_ns),
        None => (0, 0),
    };

    let step = conn_track_step(
        half_open,
        last_seen_ns,
        now_ns,
        is_syn,
        is_ack_or_rst,
        threshold,
        window_ns,
    );

    if step.half_open == 0 {
        let _ = CONN_TRACK.remove(src);
    } else {
        let entry = ConnTrackEntry {
            last_seen_ns: step.last_seen_ns,
            half_open: step.half_open,
            padding: [0; 4],
        };
        let _ = CONN_TRACK.insert(src, &entry, 0);
    }

    step.drop
}
