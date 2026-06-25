use aya_ebpf::programs::XdpContext;

use crate::maps::{BLACKLIST, EVENTS};
use eshield_common::{rules, DropEvent, IpKey};

pub fn is_blacklisted(src: &IpKey, now_ns: u64) -> bool {
    match unsafe { BLACKLIST.get(src) } {
        Some(entry) => {
            // blocked_until_ns == 0 表示永久封禁
            if entry.blocked_until_ns == 0 || entry.blocked_until_ns > now_ns {
                return true;
            }
        }
        None => return false,
    }

    // 已过期，从黑名单中移除
    let _ = BLACKLIST.remove(src);
    false
}

pub fn emit_blacklist_event(_ctx: &XdpContext, src: &IpKey, protocol: u8) {
    unsafe {
        if let Some(mut entry) = EVENTS.reserve::<DropEvent>(0) {
            let event = DropEvent {
                timestamp_ns: aya_ebpf::helpers::gen::bpf_ktime_get_ns(),
                src_ip: src.addr,
                family: src.family,
                protocol,
                rule_id: rules::BLACKLIST,
                padding: [0; 4],
            };
            entry.write(event);
            entry.submit(0);
        }
    }
}
