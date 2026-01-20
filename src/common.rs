use aya::Pod;
use std::hash::Hash;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4AddrImpl {
    pub data: u32,
}
unsafe impl Pod for Ipv4AddrImpl {}
const _: () = assert!(std::mem::size_of::<Ipv4AddrImpl>() == 4);

impl std::fmt::Display for Ipv4AddrImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", network_address_to_string(self.data))
    }
}

/// Equivalent to `struct ipv4_flow_key`
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Ipv4FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

unsafe impl Pod for Ipv4FlowKey {}

// Compile-time check: size == 12 bytes
const _: () = assert!(std::mem::size_of::<Ipv4FlowKey>() == 12);

/// Equivalent to `struct statistics`
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Statistics {
    pub ip_blocks: u64,
    pub verified: u64,
    pub dropped_packets: u64,
    pub state_switches: u64,
    pub drop_connection: u64,
    pub syn: u64,
    pub tcp_bypass: u64,
    pub incoming_bytes: u64,
    pub dropped_bytes: u64,
}

unsafe impl Pod for Statistics {}

// Compile-time check: size == 72 bytes
const _: () = assert!(std::mem::size_of::<Statistics>() == 72);

pub fn network_address_to_string(ip: u32) -> String {
    std::net::Ipv4Addr::from(ip.swap_bytes()).to_string()
}

pub fn network_port_to_normal(port: u16) -> u16 {
    port.swap_bytes()
}

impl std::fmt::Display for Ipv4FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}:{} -> {}:{}]",
            network_address_to_string(self.src_ip),
            network_port_to_normal(self.src_port),
            network_address_to_string(self.dst_ip),
            network_port_to_normal(self.dst_port)
        )
    }
}
