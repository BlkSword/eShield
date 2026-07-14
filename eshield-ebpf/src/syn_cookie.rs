use crate::parser::IpHdr;
use aya_ebpf::programs::XdpContext;

pub const NO_ACTION: u32 = u32::MAX;

/// SYN Cookie 代理暂被禁用。
///
/// 当前实现需要进一步满足 BPF verifier 对 `ctx.data_end()` 的 32->64 位零扩展限制；
/// 在修复之前返回 NO_ACTION，让 TCP SYN 包继续由 SYN Flood 速率限制模块处理。
pub fn handle_syn(_ctx: &XdpContext, _ip: *const IpHdr, _ip_hdr_len: usize) -> u32 {
    NO_ACTION
}

pub fn handle_ack(_ctx: &XdpContext, _ip: *const IpHdr, _ip_hdr_len: usize) -> u32 {
    NO_ACTION
}
