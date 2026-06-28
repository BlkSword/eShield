use aya::Ebpf;
use eshield_common::{DropEvent, IpFamily, IpKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::debug;

use crate::adaptive::AdaptiveEngine;
use crate::ip::format_ip_key;
use crate::state::Stats;

/// 消费一批 Ring Buffer 事件（最多 256 条），然后返回。
/// 调用方需要周期性地重新获取锁并调用本函数。
pub async fn run(
    stats: Arc<Stats>,
    adaptive: Arc<AdaptiveEngine>,
    ebpf: &mut Ebpf,
) -> anyhow::Result<usize> {
    // 先把事件读到本地 Vec，然后释放 RingBuf，避免与 adaptive 同时借用 ebpf
    let events: Vec<DropEvent> = {
        let mut ring_buf = aya::maps::RingBuf::try_from(
            ebpf.map_mut("EVENTS")
                .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?,
        )?;

        let mut events = Vec::with_capacity(256);
        while let Some(item) = ring_buf.next() {
            if item.len() >= std::mem::size_of::<DropEvent>() {
                let event: &DropEvent = unsafe { &*(item.as_ptr() as *const DropEvent) };
                events.push(*event);
            }
            if events.len() >= 256 {
                break;
            }
        }
        events
    };

    // 批量聚合后再更新全局 Stats，减少原子操作和 DashMap 竞争
    let mut by_source: HashMap<IpKey, u64> = HashMap::new();
    let mut by_reason: HashMap<u16, u64> = HashMap::new();
    let mut by_protocol: HashMap<u8, u64> = HashMap::new();
    let mut by_port: HashMap<u16, u64> = HashMap::new();

    let process_start = std::time::Instant::now();

    for event in &events {
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

        *by_source.entry(src_key).or_insert(0) += 1;
        *by_reason.entry(event.rule_id).or_insert(0) += 1;
        *by_protocol.entry(event.protocol).or_insert(0) += 1;
        *by_port.entry(event.dst_port).or_insert(0) += 1;

        // WAF/Challenge/GeoIP 事件由各自模块独立处理，不进入通用自适应阈值引擎
        if event.rule_id != eshield_common::rules::WAF
            && event.rule_id != eshield_common::rules::CHALLENGE
            && event.rule_id != eshield_common::rules::GEOIP
        {
            if let Err(e) = adaptive.on_event(&stats, src_key, ebpf) {
                debug!("adaptive engine error: {}", e);
            }
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

    stats.add_dropped_batch(&by_reason, &by_source, &by_protocol, &by_port);

    let elapsed_us = process_start.elapsed().as_micros() as u64;
    stats.record_process_time_us(elapsed_us);

    if events.is_empty() {
        // 无事件时让出 CPU，避免空转；使用 interval 保持一致的节奏
        let mut tick = interval(Duration::from_millis(10));
        tick.tick().await;
    }

    Ok(events.len())
}
