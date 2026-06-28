use aya_ebpf::programs::XdpContext;

use crate::maps::{EVENTS, PORT_ACL};
use eshield_common::{rules, DropEvent, IpKey};

/// 检查端口/协议 ACL 规则表。
/// 返回 true 表示应 DROP，false 表示无匹配规则（交由后续逻辑）。
pub fn check_port_acl(_ctx: &XdpContext, src: &IpKey, protocol: u8, dport: u16) -> bool {
    for i in 0..128u32 {
        let entry = match PORT_ACL.get(i) {
            Some(e) => e,
            None => continue,
        };

        // action == 0 表示空条目
        if entry.action == 0 {
            continue;
        }

        // protocol 匹配：0 表示任意
        if entry.protocol != 0 && entry.protocol != protocol {
            continue;
        }

        // 端口匹配：dport_low == 0 表示任意
        let dport_low = u16::from_be(entry.dport_low);
        let dport_high = u16::from_be(entry.dport_high);
        if dport_low != 0 {
            if dport_high != 0 {
                if dport < dport_low || dport > dport_high {
                    continue;
                }
            } else if dport != dport_low {
                continue;
            }
        }

        // action: 1 = allow, 2 = drop
        if entry.action == 2 {
            emit_port_acl_event(_ctx, src, protocol, dport);
            return true;
        }
        // 显式 allow 不再继续检查
        return false;
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
