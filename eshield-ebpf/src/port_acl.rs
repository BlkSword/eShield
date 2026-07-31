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
pub fn check_port_acl(_ctx: &XdpContext, src: &IpKey, protocol: u8, dport: u16) -> bool {
    for i in 0..128u32 {
        let entry = match PORT_ACL.get(i) {
            Some(e) => e,
            None => continue,
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
            None => continue,
        }
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
