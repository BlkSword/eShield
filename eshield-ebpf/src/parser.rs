use aya_ebpf::programs::XdpContext;
use core::mem;

pub const ETH_HDR_LEN: usize = 14;
pub const IP_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;

#[allow(dead_code)]
pub const TCP_HDR_LEN: usize = 20;

#[allow(dead_code)]
pub const UDP_HDR_LEN: usize = 8;

pub const ETH_P_IP: u16 = u16::to_be(0x0800);
pub const ETH_P_IPV6: u16 = u16::to_be(0x86dd);

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_ICMPV6: u8 = 58;

#[repr(C)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub proto: u16,
}

#[repr(C)]
pub struct IpHdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub proto: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

#[repr(C)]
pub struct Ipv6Hdr {
    pub ver_tc_fl: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

impl Ipv6Hdr {
    #[inline]
    #[allow(dead_code)]
    pub fn version(&self) -> u8 {
        (u32::from_be(self.ver_tc_fl) >> 28) as u8
    }
}

#[repr(C)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_flags: u16, // 4 bits doff + 12 bits flags
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

impl TcpHdr {
    #[inline]
    #[allow(dead_code)]
    pub fn doff(&self) -> u8 {
        (u16::from_be(self.doff_flags) >> 12) as u8
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        (u16::from_be(self.doff_flags) & 0x3f) as u8
    }
}

#[repr(C)]
#[allow(dead_code)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

#[allow(dead_code)]
pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
    IcmpV6,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(proto: u8) -> Self {
        match proto {
            IPPROTO_ICMP => Protocol::Icmp,
            IPPROTO_TCP => Protocol::Tcp,
            IPPROTO_UDP => Protocol::Udp,
            IPPROTO_ICMPV6 => Protocol::IcmpV6,
            other => Protocol::Other(other),
        }
    }
}

/// 安全的有界指针读取。如果越界返回 None。
#[inline]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return None;
    }
    Some((start + offset) as *const T)
}

/// 可变版本的有界指针。
#[inline]
pub unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return None;
    }
    Some((start + offset) as *mut T)
}
