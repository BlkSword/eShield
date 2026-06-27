use aya_ebpf::{helpers::gen::bpf_ktime_get_ns};
use eshield_common::{rules, waf_match, HttpMethod, IpKey, WafAction, WafRule, WAF_FIELD_LEN, WAF_RULES_MAX};

use crate::maps::{EVENTS, GLOBAL_STATS, WAF_RULES};
use crate::parser;

/// WAF 只检查 TCP payload 前 32 字节，使用 8 字节签名 + 掩码匹配方法与 URI 前缀。
const MAX_PAYLOAD: usize = 32;

pub fn check(ctx: &aya_ebpf::programs::XdpContext, src: &IpKey, payload_offset: usize) -> Option<u8> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + payload_offset + MAX_PAYLOAD > end {
        return None;
    }

    let payload = unsafe { *((start + payload_offset) as *const [u8; MAX_PAYLOAD]) };
    let method = HttpMethod::from_bytes(&payload);
    let path_offset = method_path_offset(method);

    for i in 0..WAF_RULES_MAX {
        let rule = match unsafe { WAF_RULES.get(i as u32) } {
            Some(r) => r,
            None => continue,
        };
        if rule.enabled == 0 {
            continue;
        }

        if rule.match_flags & waf_match::METHOD != 0 {
            if rule.method != 0 && rule.method != method as u8 {
                continue;
            }
        }

        if rule.match_flags & waf_match::PATH_PREFIX != 0 {
            if !sig_eq(&payload, path_offset, &rule.path_sig, &rule.path_mask) {
                continue;
            }
        }

        if rule.action == WafAction::Drop as u8 {
            unsafe {
                if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                    let stats = &mut *stats;
                    stats.total_dropped += 1;
                    stats.waf_blocked += 1;
                }
            }
            emit_event(src, rules::WAF);
            return Some(rule.action);
        }

        if rule.action == WafAction::Challenge as u8 {
            unsafe {
                if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                    (*stats).challenge_issued += 1;
                }
            }
            emit_event(src, rules::CHALLENGE);
            return Some(rule.action);
        } else {
            emit_event(src, rules::WAF);
        }
    }

    None
}

/// 根据 HTTP 方法返回 URI 起始固定偏移，避免在 verifier 中做动态扫描。
fn method_path_offset(method: HttpMethod) -> usize {
    match method {
        HttpMethod::Get => 4,      // "GET "
        HttpMethod::Post => 5,     // "POST "
        HttpMethod::Put => 4,      // "PUT "
        HttpMethod::Delete => 7,   // "DELETE "
        HttpMethod::Head => 5,     // "HEAD "
        HttpMethod::Options => 8,  // "OPTIONS "
        HttpMethod::Patch => 6,    // "PATCH "
        HttpMethod::Any => 0,
    }
}

fn sig_eq(payload: &[u8; MAX_PAYLOAD], offset: usize, sig: &[u8; WAF_FIELD_LEN], mask: &[u8; WAF_FIELD_LEN]) -> bool {
    if offset + WAF_FIELD_LEN > MAX_PAYLOAD {
        return false;
    }
    let chunk = u64::from_be_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
        payload[offset + 4],
        payload[offset + 5],
        payload[offset + 6],
        payload[offset + 7],
    ]);
    let sig_val = u64::from_be_bytes(*sig);
    let mask_val = u64::from_be_bytes(*mask);
    (chunk & mask_val) == (sig_val & mask_val)
}

fn emit_event(src: &IpKey, rule_id: u16) {
    if let Some(mut entry) = EVENTS.reserve::<eshield_common::DropEvent>(0) {
        let event = entry.as_mut_ptr() as *mut eshield_common::DropEvent;
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).src_ip = src.addr;
            (*event).family = src.family;
            (*event).protocol = parser::IPPROTO_TCP;
            (*event).rule_id = rule_id;
        }
        entry.submit(0);
    }
}
