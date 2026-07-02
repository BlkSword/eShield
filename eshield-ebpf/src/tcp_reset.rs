use aya_ebpf::programs::XdpContext;
use aya_ebpf::bindings::xdp_action;
use aya_ebpf::helpers::gen::{bpf_csum_diff, bpf_xdp_adjust_tail};
use core::mem;

use crate::maps::GLOBAL_STATS;
use crate::parser::{EthHdr, IpHdr, TcpHdr, ETH_HDR_LEN, IPPROTO_TCP};

const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const IPV4_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;
const RST_PKT_LEN: u16 = (IPV4_HDR_LEN + TCP_HDR_LEN) as u16;

#[inline(always)]
fn inc_rst_sent() {
    unsafe {
        if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
            (*stats).tcp_rst_sent += 1;
        }
    }
}

#[inline(always)]
fn inc_rst_fail() {
    unsafe {
        if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
            (*stats).tcp_rst_fail += 1;
        }
    }
}

/// For an IPv4 TCP packet that is about to be dropped, turn it into a TCP RST
/// and transmit it back out the same interface (XDP_TX).
#[inline(always)]
pub fn reply_tcp_rst(ctx: &XdpContext, ip_hdr_len: usize) -> u32 {
    if ip_hdr_len == IPV4_HDR_LEN {
        reply_tcp_rst_v4(ctx)
    } else {
        // IPv6 RST is more complex (no IP checksum but larger pseudo-header).
        // Keep behaviour conservative: fall back to silent drop.
        inc_rst_fail();
        xdp_action::XDP_DROP
    }
}

#[inline(always)]
fn reply_tcp_rst_v4(ctx: &XdpContext) -> u32 {
    // The caller already verified ip_hdr_len == 20; shrink the packet to
    // Ethernet + IPv4 + 20-byte TCP header so the IPv4 total length matches
    // the actual frame length for XDP_TX.
    let cur_len = (ctx.data_end() - ctx.data()) as i32;
    let target_len = (ETH_HDR_LEN + RST_PKT_LEN as usize) as i32;
    let delta = target_len - cur_len;
    if unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) } != 0 {
        inc_rst_fail();
        return xdp_action::XDP_DROP;
    }

    // Re-derive header pointers after the tail adjustment.
    let eth: *mut EthHdr = match unsafe { ptr_at_mut(ctx, 0) } {
        Some(p) => p,
        None => { inc_rst_fail(); return xdp_action::XDP_DROP; }
    };
    let ip: *mut IpHdr = match unsafe { ptr_at_mut(ctx, ETH_HDR_LEN) } {
        Some(p) => p,
        None => { inc_rst_fail(); return xdp_action::XDP_DROP; }
    };
    let tcp: *mut TcpHdr = match unsafe { ptr_at_mut(ctx, ETH_HDR_LEN + IPV4_HDR_LEN) } {
        Some(p) => p,
        None => { inc_rst_fail(); return xdp_action::XDP_DROP; }
    };

    unsafe {
        // Only handle TCP.
        if (*ip).proto != IPPROTO_TCP {
            inc_rst_fail();
            return xdp_action::XDP_DROP;
        }

        // Swap Ethernet MAC addresses.
        let src_mac = (*eth).src;
        (*eth).src = (*eth).dst;
        (*eth).dst = src_mac;

        // Swap IPv4 addresses.
        let src_ip = (*ip).saddr;
        (*ip).saddr = (*ip).daddr;
        (*ip).daddr = src_ip;

        // Swap TCP ports.
        let src_port = (*tcp).source;
        (*tcp).source = (*tcp).dest;
        (*tcp).dest = src_port;

        // Build RST|ACK response: ack = incoming seq + 1.
        let incoming_seq = u32::from_be((*tcp).seq);
        (*tcp).seq = 0;
        (*tcp).ack_seq = u32::to_be(incoming_seq.wrapping_add(1));

        let flags = TCP_FLAG_RST | TCP_FLAG_ACK;
        let doff = 5u16; // 20 bytes TCP header
        (*tcp).doff_flags = u16::to_be((doff << 12) | (flags as u16));
        (*tcp).window = 0;
        (*tcp).urg_ptr = 0;

        // Zero checksums before recomputing and rewrite IPv4 total length.
        (*ip).check = 0;
        (*tcp).check = 0;
        (*ip).tot_len = u16::to_be(RST_PKT_LEN);

        // Recompute IPv4 header checksum using the kernel helper.
        let ip_check = csum(ctx, ETH_HDR_LEN, IPV4_HDR_LEN, 0);
        if ip_check < 0 {
            inc_rst_fail();
            return xdp_action::XDP_DROP;
        }
        (*ip).check = finalize_csum(ip_check);

        // Build IPv4 pseudo-header incrementally to keep stack usage tiny.
        // Pseudo-header bytes: saddr(4) + daddr(4) + 0 + proto + 0 + len(2).
        let mut word: u32 = (*ip).saddr;
        let mut pseudo_sum = bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            &mut word as *mut u32,
            4,
            0,
        );
        if pseudo_sum < 0 {
            inc_rst_fail();
            return xdp_action::XDP_DROP;
        }
        word = (*ip).daddr;
        pseudo_sum = bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            &mut word as *mut u32,
            4,
            pseudo_sum as u32,
        );
        if pseudo_sum < 0 {
            inc_rst_fail();
            return xdp_action::XDP_DROP;
        }
        // Last pseudo-header word as little-endian bytes [0, proto, 0, len].
        word = ((IPPROTO_TCP as u32) << 8) | ((TCP_HDR_LEN as u32) << 24);
        pseudo_sum = bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            &mut word as *mut u32,
            4,
            pseudo_sum as u32,
        );
        if pseudo_sum < 0 {
            inc_rst_fail();
            return xdp_action::XDP_DROP;
        }

        let tcp_check = csum(
            ctx,
            ETH_HDR_LEN + IPV4_HDR_LEN,
            TCP_HDR_LEN,
            pseudo_sum as u32,
        );
        if tcp_check < 0 {
            inc_rst_fail();
            return xdp_action::XDP_DROP;
        }
        (*tcp).check = finalize_csum(tcp_check);
    }

    inc_rst_sent();
    xdp_action::XDP_TX
}

/// Compute one's-complement sum of a packet region using the kernel helper.
#[inline(always)]
fn csum(ctx: &XdpContext, offset: usize, len: usize, seed: u32) -> i64 {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + len > end {
        return -1;
    }
    unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            (start + offset) as *mut u32,
            len as u32,
            seed,
        )
    }
}

/// Fold a 32-bit one's-complement accumulator into the final checksum.
#[inline(always)]
fn finalize_csum(sum: i64) -> u16 {
    let mut v = sum as u32;
    v = (v & 0xffff) + (v >> 16);
    v = (v & 0xffff) + (v >> 16);
    let r = !(v as u16);
    if r == 0 { 0xffff } else { r }
}

// Mutable pointer helper (mirrors parser::ptr_at but returns *mut T).
#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return None;
    }
    Some((start + offset) as *mut T)
}
