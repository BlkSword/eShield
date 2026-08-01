use aya_ebpf::programs::XdpContext;

use crate::maps::{EVENTS, PORT_ACL};
use eshield_common::pure::{match_port_acl_entry, AclMatch};
use eshield_common::{rules, DropEvent, IpKey};

/// 检查端口/协议 ACL 规则表。
///
/// 规则按数组顺序进行 first-match 评估：
/// - `action == 2 (drop)` 且匹配时立即 DROP 并返回 true。
/// - `action == 1 (allow)` 且匹配时立即放行并返回 false，后续规则不再评估。
/// - 无匹配规则时返回 false，交由后续全局模块处理。
///
/// `count` 为控制面同步的实际规则条数，空表时跳过整个循环（性能优化）。
pub fn check_port_acl(_ctx: &XdpContext, src: &IpKey, protocol: u8, dport: u16, count: u8) -> bool {
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
            Some(AclMatch::Drop) => {
                emit_port_acl_event(_ctx, src, protocol, dport);
                return true;
            }
            Some(AclMatch::Allow) => return false,
            None => {}
        }
        i += 1;
    }

    false
}

fn emit_port_acl_event(_ctx: &XdpContext, src: &IpKey, protocol: u8, dst_port: u16) {
    unsafe {
        if let Some(mut entry) = EVENTS.reserve::<DropEvent>(0) {
            let event = DropEvent {
                timestamp_ns: aya_ebpf::helpers::gen::bpf_ktime_get_ns(),
                src_ip: src.addr,
                family: src.family,
                protocol,
                rule_id: rules::PORT_ACL,
                dst_port,
                padding: [0; 2],
            };
            entry.write(event);
            entry.submit(0);
        }
    }
}
