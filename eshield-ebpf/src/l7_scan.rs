use aya_ebpf::programs::XdpContext;

use crate::maps::{CONFIG, EVENTS, L7_PATTERNS};
use crate::parser::{ptr_at, TcpHdr, ETH_HDR_LEN};
use eshield_common::{rules, DropEvent, IpKey};

const MAX_PATTERNS: u32 = 16;
const SIGNATURE_BYTES: usize = 8;

/// 读取 TCP 载荷前 8 字节进行轻量指纹匹配。
/// 返回 true 表示命中并应 DROP。
#[inline(always)]
pub fn scan(ctx: &XdpContext, src: &IpKey, ip_hdr_len: usize, protocol: u8, dport: u16) -> bool {
    let runtime = match CONFIG.get(0) {
        Some(c) => *c,
        None => return false,
    };

    if runtime.l7_scan_enabled == 0 {
        return false;
    }

    // 仅处理 TCP 协议
    if protocol != 6 {
        return false;
    }

    let tcp_hdr: *const TcpHdr = match unsafe { ptr_at::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len) } {
        Some(t) => t,
        None => return false,
    };

    let tcp_hdr_len = (unsafe { (*tcp_hdr).doff() } as usize) * 4;
    let payload_off = ETH_HDR_LEN + ip_hdr_len + tcp_hdr_len;

    let start = ctx.data();
    let end = ctx.data_end();

    // 确保能读取 8 字节载荷；payload_off 是变量，但常数上界比较可被验证器接受。
    if start + payload_off + SIGNATURE_BYTES > end {
        return false;
    }

    let payload = (start + payload_off) as *const u64;
    // SAFETY：上面的边界检查保证了 8 字节可读。
    let chunk = unsafe { *payload };

    let mut i: u32 = 0;
    while i < MAX_PATTERNS {
        let pat = match L7_PATTERNS.get(i) {
            Some(p) => p,
            None => {
                i += 1;
                continue;
            }
        };

        if pat.length == 0 {
            i += 1;
            continue;
        }

        if (chunk & pat.mask) == (pat.signature & pat.mask) {
            emit_l7_event(ctx, src, dport);
            return true;
        }

        i += 1;
    }

    false
}

fn emit_l7_event(_ctx: &XdpContext, src: &IpKey, dst_port: u16) {
    unsafe {
        if let Some(mut entry) = EVENTS.reserve::<DropEvent>(0) {
            let event = DropEvent {
                timestamp_ns: aya_ebpf::helpers::gen::bpf_ktime_get_ns(),
                src_ip: src.addr,
                family: src.family,
                protocol: 6,
                rule_id: rules::L7_PATTERN,
                dst_port,
                padding: [0; 2],
            };
            entry.write(event);
            entry.submit(0);
        }
    }
}
