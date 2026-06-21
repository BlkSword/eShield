use aya_ebpf::programs::XdpContext;
use core::mem;

pub const ETH_HDR_LEN: usize = 14;
pub const IP_HDR_LEN: usize = 20;

#[allow(dead_code)]
pub const TCP_HDR_LEN: usize = 20;

#[allow(dead_code)]
pub const UDP_HDR_LEN: usize = 8;

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
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(proto: u8) -> Self {
        match proto {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
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
