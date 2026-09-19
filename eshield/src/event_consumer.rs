use aya::maps::{MapData, RingBuf};
use aya::Ebpf;
use eshield_common::{DropEvent, IpFamily, IpKey};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::debug;

use crate::adaptive::AdaptiveEngine;
use crate::ip::format_ip_key;
use crate::state::Stats;

/// 消费一批 Ring Buffer 事件（最多 4096 条），然后返回。
/// `ring_buf` 由调用方全生命周期持有：aya RingBuf 会缓存 producer 位置，
/// 每批重建句柄会使 consumer 位置越过 producer，导致已消费事件被无限重读。
/// `ebpf` 仅供自适应引擎在触发时写 map 使用。
pub async fn run(
    stats: Arc<Stats>,
    adaptive: Arc<AdaptiveEngine>,
    ring_buf: &mut RingBuf<MapData>,
    ebpf: &mut Ebpf,
) -> anyhow::Result<usize> {
    // 先把事件读到本地 Vec，然后释放 RingBuf 借用，避免与 adaptive 同时借用 ebpf
    let events: Vec<DropEvent> = {
        let mut events = Vec::with_capacity(4096);
        while let Some(item) = ring_buf.next() {
            if item.len() >= std::mem::size_of::<DropEvent>() {
                let event: &DropEvent = unsafe { &*(item.as_ptr() as *const DropEvent) };
                events.push(*event);
            }
            if events.len() >= 4096 {
                break;
            }
        }
        events
    };

    let process_start = std::time::Instant::now();
    let program_start_ns = stats.program_start_ns.load(Ordering::Relaxed);

    // 先过滤 stale 事件，得到本批有效事件；攻击事件一次性写入环形缓冲，
    // 避免每个事件都拿一次 Stats 的 Mutex。
    let valid_events: Vec<DropEvent> = events
        .into_iter()
        .filter(|event| {
            !(program_start_ns != 0
                && event.timestamp_ns.saturating_add(1_000_000_000) < program_start_ns)
        })
        .collect();
    stats.push_attack_events(&valid_events);

    // 按目的端口聚合；Top 攻击源由 eBPF TOP_ATTACKERS Map 直接维护。
    let mut by_port: HashMap<u16, u64> = HashMap::new();
    // 自适应引擎按源 IP 聚合本批事件，避免逐事件写 DashMap。
    let mut adaptive_counts: HashMap<IpKey, u64> = HashMap::new();

    for event in &valid_events {
        let src_key = match IpFamily::from_u8(event.family) {
            Some(IpFamily::Ipv4) => IpKey::from_ipv4([
                event.src_ip[12],
                event.src_ip[13],
                event.src_ip[14],
                event.src_ip[15],
            ]),
            Some(IpFamily::Ipv6) => IpKey::from_ipv6(event.src_ip),
            None => continue,
        };

        *by_port.entry(event.dst_port).or_insert(0) += 1;

        // GeoIP / SYN Flood / UDP Flood / ICMP Flood / Blacklist 事件
        // 已由 eBPF 数据面直接处理（加入黑名单或丢弃），不再进入自适应引擎，
        // 避免海量事件反复触发 DashMap 操作导致 CPU 占满。
        // L7 指纹与端口 ACL 命中也会进入自适应引擎，用于对反复触发的源提升封禁时长。
        if adaptive.is_enabled()
            && event.rule_id != eshield_common::rules::GEOIP
            && event.rule_id != eshield_common::rules::SYN_FLOOD
            && event.rule_id != eshield_common::rules::UDP_FLOOD
            && event.rule_id != eshield_common::rules::ICMP_FLOOD
            && event.rule_id != eshield_common::rules::BLACKLIST
        {
            *adaptive_counts.entry(src_key).or_insert(0) += 1;
        }

        debug!(
            event_type = "drop",
            src_ip = format_ip_key(&src_key),
            dst_port = event.dst_port,
            protocol = event.protocol,
            rule = event.rule_id,
            action = "drop",
            reason = event.rule_id,
            "drop event"
        );
    }

    for (src_key, count) in adaptive_counts {
        if let Err(e) = adaptive.on_events(&stats, src_key, count, ebpf) {
            debug!("adaptive engine error: {}", e);
        }
    }

    stats.add_dropped_batch(&by_port);

    if !valid_events.is_empty() {
        tracing::debug!(
            events_len = valid_events.len(),
            ?by_port,
            "event_consumer batch"
        );
    }

    let elapsed_us = process_start.elapsed().as_micros() as u64;
    stats.record_process_time_us(elapsed_us);

    if valid_events.is_empty() {
        // 无事件时让出 CPU，避免空转；使用 interval 保持一致的节奏
        let mut tick = interval(Duration::from_millis(10));
        tick.tick().await;
    }

    Ok(valid_events.len())
}
