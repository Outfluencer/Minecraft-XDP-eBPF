use aya::Pod;
use std::hash::Hash;

/// Equivalent to `struct ipv4_flow_key`
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

pub fn flow_key_to_string(key: &Ipv4FlowKey) -> String {
    format!(
        "[{}:{} -> {}:{}]",
        network_address_to_string(key.src_ip),
        network_port_to_normal(key.src_port),
        network_address_to_string(key.dst_ip),
        network_port_to_normal(key.dst_port)
    )
}
