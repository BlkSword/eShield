use aya::Ebpf;
use eshield_common::DropEvent;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::debug;

use crate::adaptive::AdaptiveEngine;
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

    for event in &events {
        stats.add_dropped(event.src_ip);

        if let Err(e) = adaptive.on_event(&stats, event.src_ip, ebpf) {
            debug!("adaptive engine error: {}", e);
        }

        debug!(
            "drop event: src={:#x}, proto={}, rule={}",
            event.src_ip, event.protocol, event.rule_id
        );
    }

    if events.is_empty() {
        sleep(Duration::from_millis(10)).await;
    }

    Ok(events.len())
}
