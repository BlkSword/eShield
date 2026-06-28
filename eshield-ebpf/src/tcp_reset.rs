use aya_ebpf::programs::XdpContext;
use aya_ebpf::bindings::xdp_action;
use aya_ebpf::helpers::gen::{bpf_csum_diff, bpf_xdp_adjust_tail};
use aya_log_ebpf::debug;
use core::mem;

use crate::parser::{EthHdr, IpHdr, TcpHdr, ETH_HDR_LEN, IPPROTO_TCP};

const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const IPV4_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;
const RST_PKT_LEN: u16 = (IPV4_HDR_LEN + TCP_HDR_LEN) as u16;

/// For an IPv4 TCP packet that is about to be dropped, turn it into a TCP RST
/// and transmit it back out the same interface (XDP_TX).
///
/// Returns `XDP_TX` on success, or `XDP_DROP` if the packet is not a TCP packet
/// or cannot be rewritten safely.
#[inline(never)]
pub fn reply_tcp_rst(ctx: &XdpContext, ip_hdr_len: usize) -> u32 {
    if ip_hdr_len == IPV4_HDR_LEN {
        reply_tcp_rst_v4(ctx)
    } else {
        // IPv6 RST is more complex (no IP checksum but larger pseudo-header).
        // Keep behaviour conservative: fall back to silent drop.
        xdp_action::XDP_DROP
    }
}

#[inline(never)]
fn reply_tcp_rst_v4(ctx: &XdpContext) -> u32 {
    debug!(ctx, "reply_tcp_rst_v4 enter");

    // Only handle IPv4 with standard 20-byte IP header.  The caller already
    // verified ip_hdr_len == 20; this check also proves the packet is long
    // enough for the headers we are about to rewrite.
    let _eth: *mut EthHdr = match unsafe { ptr_at_mut(ctx, 0) } {
        Some(p) => p,
        None => return xdp_action::XDP_DROP,
    };
    let _ip: *mut IpHdr = match unsafe { ptr_at_mut(ctx, ETH_HDR_LEN) } {
        Some(p) => p,
        None => return xdp_action::XDP_DROP,
    };
    let _tcp: *mut TcpHdr = match unsafe { ptr_at_mut(ctx, ETH_HDR_LEN + IPV4_HDR_LEN) } {
        Some(p) => p,
        None => return xdp_action::XDP_DROP,
    };

    // Shrink the packet to Ethernet + IPv4 + 20-byte TCP header.  This removes
    // any TCP options that may have been present in the incoming SYN so that
    // the IPv4 total length matches the actual frame length for XDP_TX.
    let cur_len = (ctx.data_end() - ctx.data()) as i32;
    let target_len = (ETH_HDR_LEN + RST_PKT_LEN as usize) as i32;
    let delta = target_len - cur_len;
    if unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) } != 0 {
        debug!(ctx, "reply_tcp_rst_v4 adjust_tail failed");
        return xdp_action::XDP_DROP;
    }

    // Re-derive header pointers after the tail adjustment.
    let eth: *mut EthHdr = match unsafe { ptr_at_mut(ctx, 0) } {
        Some(p) => p,
        None => return xdp_action::XDP_DROP,
    };
    let ip: *mut IpHdr = match unsafe { ptr_at_mut(ctx, ETH_HDR_LEN) } {
        Some(p) => p,
        None => return xdp_action::XDP_DROP,
    };
    let tcp: *mut TcpHdr = match unsafe { ptr_at_mut(ctx, ETH_HDR_LEN + IPV4_HDR_LEN) } {
        Some(p) => p,
        None => return xdp_action::XDP_DROP,
    };

    unsafe {
        // Only handle TCP.
        if (*ip).proto != IPPROTO_TCP {
            debug!(ctx, "reply_tcp_rst_v4 not tcp proto={}", (*ip).proto as u32);
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

        // Build RST|ACK response.
        // ack = incoming seq + 1.
        let incoming_seq = u32::from_be((*tcp).seq);
        (*tcp).seq = 0;
        (*tcp).ack_seq = u32::to_be(incoming_seq.wrapping_add(1));

        let flags = TCP_FLAG_RST | TCP_FLAG_ACK;
        let doff = 5u16; // 20 bytes TCP header
        (*tcp).doff_flags = u16::to_be((doff << 12) | (flags as u16));
        (*tcp).window = 0;
        (*tcp).urg_ptr = 0;

        // Zero checksums before recomputing.
        (*ip).check = 0;
        (*tcp).check = 0;

        // Rewrite IPv4 total length to match the RST packet (no payload).
        (*ip).tot_len = u16::to_be(RST_PKT_LEN);

        // Recompute IPv4 header checksum using the kernel helper.
        let ip_check = csum(ctx, ETH_HDR_LEN, IPV4_HDR_LEN, 0);
        if ip_check < 0 {
            return xdp_action::XDP_DROP;
        }
        (*ip).check = finalize_csum(ip_check);

        // Build IPv4 pseudo-header on stack and compute TCP checksum.
        // saddr/daddr are read from the packet as little-endian u32s but the
        // underlying bytes are already in network order, so use to_le_bytes()
        // to recover the original packet bytes.
        let saddr = (*ip).saddr;
        let daddr = (*ip).daddr;
        let saddr_bytes = saddr.to_le_bytes();
        let daddr_bytes = daddr.to_le_bytes();
        let mut pseudo = [0u8; 12];
        pseudo[0] = saddr_bytes[0];
        pseudo[1] = saddr_bytes[1];
        pseudo[2] = saddr_bytes[2];
        pseudo[3] = saddr_bytes[3];
        pseudo[4] = daddr_bytes[0];
        pseudo[5] = daddr_bytes[1];
        pseudo[6] = daddr_bytes[2];
        pseudo[7] = daddr_bytes[3];
        pseudo[8] = 0;
        pseudo[9] = IPPROTO_TCP;
        pseudo[10] = 0;
        pseudo[11] = TCP_HDR_LEN as u8;

        let pseudo_sum = bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            pseudo.as_ptr() as *mut u32,
            pseudo.len() as u32,
            0,
        );
        if pseudo_sum < 0 {
            return xdp_action::XDP_DROP;
        }

        let tcp_check = csum(
            ctx,
            ETH_HDR_LEN + IPV4_HDR_LEN,
            TCP_HDR_LEN,
            pseudo_sum as u32,
        );
        if tcp_check < 0 {
            return xdp_action::XDP_DROP;
        }
        (*tcp).check = finalize_csum(tcp_check);
    }

    debug!(ctx, "reply_tcp_rst_v4 returning XDP_TX");
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
