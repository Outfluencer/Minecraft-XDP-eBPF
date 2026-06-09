use aya::Pod;

/// Equivalent to `struct statistics`
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Statistics {
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

// Compile-time check: size == 64 bytes
const _: () = assert!(std::mem::size_of::<Statistics>() == 64);
