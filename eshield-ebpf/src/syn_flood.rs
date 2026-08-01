use crate::blacklist::add_to_blacklist;
use crate::rate_counter::{update_rate_counter, RateUpdate};
use eshield_common::{rules, IpKey};

/// TCP flags
const TCP_FLAG_SYN: u8 = 0x02;

/// 检测并处理 SYN Flood：对单 IP 的 SYN 包做速率限制，超限即 DROP 并加黑名单。
/// 不接收 ctx：本函数只做 map 操作，无需包内存访问。

pub fn handle_syn_flood(src: &IpKey, tcp_flags: u8, now_ns: u64) -> bool {
    if tcp_flags != TCP_FLAG_SYN {
        return false;
    }

    let mut update = RateUpdate {
        counter: 0,
        threshold: 0,
        block_duration_s: 0,
    };
    if !update_rate_counter(src, now_ns, &mut update) {
        return false;
    }

    if update.counter > update.threshold {
        add_to_blacklist(src, now_ns, update.block_duration_s, rules::SYN_FLOOD as u8);
        return true;
    }

    false
}
