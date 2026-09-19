use crate::maps::PORT_ACL;
use eshield_common::pure::{match_port_acl_entry, AclMatch};

/// 检查端口/协议 ACL 规则表。
///
/// 规则按数组顺序进行 first-match 评估：
/// - `action == 2 (drop)` 且匹配时返回 true，由主流程统一 DROP/发事件。
/// - `action == 1 (allow)` 且匹配时返回 false，停止继续匹配 ACL，
///   但该包仍会经过 GeoIP/Flood/L7/限速/黑名单等全局模块。
/// - 无匹配规则时返回 false，交由后续全局模块处理。
///
/// DROP 事件由主流程 `drop_packet` 统一写入 EVENTS；本函数不再重复发事件。
/// `count` 为控制面同步的实际规则条数，空表时跳过整个循环（性能优化）。
pub fn check_port_acl(protocol: u8, dport: u16, count: u8) -> bool {
    // while 循环：避免 for-range 迭代器生成 u32→u64 零扩展（<<=）指令，
    // 该模式在部分内核的 verifier 上被拒绝（pointer arithmetic with <<=）。
    let mut i: u64 = 0;
    while i < count as u64 {
        let entry = match PORT_ACL.get(i as u32) {
            Some(e) => e,
            None => {
                i += 1;
                continue;
            }
        };

        let dport_low = u16::from_be(entry.dport_low);
        let dport_high = u16::from_be(entry.dport_high);

        match match_port_acl_entry(
            protocol,
            dport,
            entry.protocol,
            dport_low,
            dport_high,
            entry.action,
        ) {
            Some(AclMatch::Drop) => return true,
            Some(AclMatch::Allow) => return false,
            None => {}
        }
        i += 1;
    }

    false
}
