#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
// fuck this htons method
#define htons(x) ((uint16_t)((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8)))

// MAX LENGTH'S

// PACKET LEN - PACKET ID - DATA
const int MIN_HANDSHAKE_LEN = 1 + 1 + 1 + 2 + 2 + 1;
const int MAX_HANDSHAKE_LEN = 2 + 1 + 5 + (255 * 3) + 2;
const int MIN_LOGIN_LEN = 1 + 1 + 2; // drop empty names instantly
const int PING_REQUEST_LEN = 10; // drop empty names instantly

// #define SIGNATURE_LOGIN

#ifdef SIGNATURE_LOGIN
    const int MAX_LOGIN_LEN = 2 + 1 + (16 * 3) + 1 + 8 + 512 + 2 + 4096 + 2;
#else
    const int MAX_LOGIN_LEN = 2 + 1 + (16 * 3) + 1 + 16;    
#endif

// STATE TRACKING

const __u8 AWAIT_ACK = 1;
const __u8 AWAIT_STATUS_REQUEST = 3;
const __u8 AWAIT_LOGIN = 4;
const __u8 AWAIT_PING = 5;

const __u8 AWAIT_MC_HANDSHAKE = 10; // counting this higher is alowed for counting invalid packets


const int DISABLE_FILTER = 1000;

// Connection tracking map (LRU) to track active flows (both TCP and UDP)
struct flow_key_t { __u64 key; };  // dummy struct to align 64-bit key if needed
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // flow 5-tuple key
    __type(value, __u8); // current state
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u64);   // flow 5-tuple key
    __type(value, __u64); // last seen timestamp (ns) or state info
} player_connection_map SEC(".maps");

// *** Helper Functions ***

// Parse TCP header (returns NULL if out-of-bounds)
static __always_inline struct tcphdr *parse_tcp(void *data, void *data_end, struct iphdr *ip) {
    struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + sizeof(struct iphdr));
    if ((void *)(tcp + 1) > data_end) {
        return NULL; // Packet not large enough for TCP header
    }
    return tcp;
}

// Generate a 64-bit flow key from 5-tuple (src/dst IPs and ports, protocol)
static __always_inline __u64 generate_flow_key(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol) {
    // Combine into 64 bits: 32 bits of src_ip, 16 bits of src_port, 8 bits of proto, 8 bits of dst_port (low 8 bits)
    // This is a simple combination; it should uniquely identify flows in this context.
    __u64 key = 0;
    key |= (__u64)src_ip << 32;
    key |= (__u64)src_port << 16;
    key |= (__u64)protocol << 8;
    key |= (__u64)(dst_port & 0xFF);
    // (Note: if needed, include dst_ip and full ports for complete uniqueness, but here assume server IP/port fixed)
    return key;
}




// Check for TCP bypass attempt via abnormal flags or state
static __always_inline int detect_tcp_bypass(struct tcphdr *tcp) {
    // Drop any packet with no control flags (NULL scan) or an unsolicited SYN-ACK
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) ||   // no SYN/ACK/FIN/RST flag
        (tcp->syn && tcp->ack)) {                               // SYN+ACK from external (unexpected)
        return 1;  // suspected bypass/scanning packet
    }
    // Drop if URG flag is set (rarely legitimate, often used in attacks to evade filters)
    if (tcp->urg) {
        return 1;
    }
    return 0;
}


static __always_inline int inspect_status_request(void *data, void *data_end) {
    __u8 *start = (__u8 *)data;
    __u8 *end = (__u8 *)data_end;
    __u32 size = end - start;
    if (size != 2) return 0;

    if (start < end) {
        if (*(signed char *)(start) != 1) {
            return 0;
        }
    } 

    if (start + 1 < end) {
        if (*(signed char *)(start + 1) != 0) {
            return 0;
        }
    } 
    return 1;
}

static __always_inline int inspect_login_packet(void *data, void *data_end) {
    __u8 *start = (__u8 *)data;
    __u8 *end = (__u8 *)data_end;
    __u32 size = end - start;
    if (size < MIN_LOGIN_LEN || size > MAX_LOGIN_LEN) return 0; 
    #ifndef SIGNATURE_LOGIN
        if (start + 1 < end) {
            signed char c = *(signed char *)(start + 1);
            if (c != 0) { // packet id musst be 0;
                return 0;
            }
        } 
    #endif
    return 1;
}



static __always_inline int inspect_handshake(void *data, void *data_end) {
    __u8 *start = (__u8 *)data;
    __u8 *end = (__u8 *)data_end;
    __u32 size = end - start;
    if (size > MAX_HANDSHAKE_LEN + MAX_LOGIN_LEN || size < MIN_HANDSHAKE_LEN) return 0; // + 1 + (16*3) + 1 + 8 +512+4096 + 5 + 5
    __u32 position = 0;
    int packetLen = 0;
    if (start < end) {
	    signed char byte = *(signed char *)(start);
	    if (byte < 0) { // i dont care & 0x80 same tho
            if (start + 1 < end) {
                signed char byte2 = *(signed char *)(start + 1);
                if (byte2 < 0) {
                    // to long handshake fuck this connection
                    return 0;
                } 
                if (start + 2 < end) {
                    signed char packetId = *(signed char *)(start + 2); // should always be 0
                    if (packetId != 0) {
                        // invalid packet id
                        return 0;
                    }
                } else {
                    return 0;
                }

                packetLen = (byte & 0x7F) | (byte2 << 7) + 2;
                position = 3;
            } else {
                return 0;
            }
	    } else {
            if (start + 1 < end) {
                signed char packetId = *(signed char *)(start + 1); // should always be 0
                if (packetId != 0) {
                    // invalid packet id
                    return 0;
                }
            } else {
                return 0;
            }
            packetLen = byte + 1;
            position = 2;
	    }
	} else {
        return 0;
    }

    int protocol_version = 0;
    if (start + position < end) {
        signed char firstByte = *(signed char *)(start + position);
        if (firstByte < 0) {
            position = position + 1;
            if (start + position < end) {
                signed char secondByte = *(signed char *)(start + position);
                if ( secondByte < 0) {
                    // protocol took more than 2 bytes varint
                    return 0;
                }
                protocol_version = (firstByte & 0x7F) | (secondByte << 7);
            } else {
                return 0;
            }
        } else {
            protocol_version = firstByte;
        }
    } else {
        return 0;
    }


    position = position + 1;
    int host_len = 0;
    if (start + position < end) {
        signed char firstByte = *(signed char *)(start + position);
        if (firstByte < 0) {
            position = position + 1;
            if (start + position < end) {
                signed char secondByte = *(signed char *)(start + position);
                if ( secondByte < 0) {
                    return 0;
                }
                host_len = (firstByte & 0x7F) | (secondByte << 7);
            } else {
                return 0;
            }
        } else {
            host_len = firstByte;
        }
    } else {
        return 0;
    }

    if (host_len > 255 || host_len < 1) {
        return 0;
    }

    if (size < packetLen) {
        return 0;
    }


    __u8 *last_byte_ptr = start + (packetLen - 1);
    int intention = 0;
    if (last_byte_ptr + 1 <= end) {
        intention = *last_byte_ptr;
        if (intention != 1 && intention != 2 && intention != 3) {
            return 0;
        }
    } else {
        return 0;
    }

    // this packet only contained the handshake
    if(size == packetLen) {
        if (intention == 1) {
            return AWAIT_STATUS_REQUEST;
        }
        return AWAIT_LOGIN;
    } else { // more data probably after retransmition
        if (intention == 1) {
            last_byte_ptr = last_byte_ptr + 1;
            if (last_byte_ptr + 2 <= end) {
                if (inspect_status_request((void *) last_byte_ptr, data_end)) {
                    return AWAIT_PING;
                }
            }
        } else {
            last_byte_ptr = last_byte_ptr + 1;
            if (inspect_login_packet((void *) last_byte_ptr, data_end)) {
                // we received login here we have to disable the filter
                return DISABLE_FILTER;
            }
        }
    }


   return 0;
}

static __always_inline int inspect_ping_request(void *data, void *data_end) {
    __u8 *start = (__u8 *)data;
    __u8 *end = (__u8 *)data_end;
    __u32 size = end - start;
    if (size != PING_REQUEST_LEN) return 0; 

    if (*(signed char *)(start) != 9) { // len
        return 0;
    }

    if (start + 1 < end) {
        if (*(signed char *)(start + 1) != 1) { // packet id
            return 0;
        }
    } 
    return 1;
}

SEC("xdp")
int minecraft_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_ABORTED;
    }

    // Only handle IPv4 packets (IPv6 or others are passed through)
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IPv4 header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_ABORTED;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Prepare a flow key for tracking (we'll fill it based on protocol below)
    // Parse TCP header
    struct tcphdr *tcp = parse_tcp(data, data_end, ip);
    if (!tcp) {
        return XDP_ABORTED;
    }

    // Check if TCP destination port matches mc server port
    if (tcp->dest != htons(25577)) {
        return XDP_PASS;  // not for our service
    }

    // Additional TCP bypass checks for abnormal flags
    if (detect_tcp_bypass(tcp)) {
        return XDP_DROP;
    }

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // Compute flow key for TCP connection
    __u64 flow_key = generate_flow_key(src_ip, dst_ip, tcp->source, tcp->dest, IPPROTO_TCP);
    __u64 *lastTime = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (lastTime != NULL) {
        __u64 now = bpf_ktime_get_ns();
        if (*lastTime + 1000000000 < now) {
            bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
        }
        return XDP_PASS;
    }


    __u8 *initial_connection_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    
    if (initial_connection_state == NULL) {
        // No entry found: if this is not a new SYN, it's an out-of-state packet -> drop
        
        if ((tcp->rst || tcp->fin) && !tcp ->psh) { // let them close the connection, better for us
            return XDP_PASS;
        }

        if (tcp->syn && !tcp->ack) {
            // Otherwise, it's a valid new SYN, create a new flow entry
            bpf_map_update_elem(&conntrack_map, &flow_key, &AWAIT_ACK, BPF_ANY);
            return XDP_PASS;
        } else {
            return XDP_DROP;
        }
    } else if (*initial_connection_state == AWAIT_ACK) {
        if (!tcp->ack || tcp->psh) {
            return XDP_DROP;
        }
        bpf_map_update_elem(&conntrack_map, &flow_key, &AWAIT_MC_HANDSHAKE, BPF_ANY);
	    *initial_connection_state = AWAIT_MC_HANDSHAKE;	
    }

    void *tcp_payload = (void *)((__u8 *)tcp + (tcp->doff * 4));
    if (tcp_payload < data_end) { 
        __u8 currentState = *initial_connection_state;
        if (currentState >= AWAIT_MC_HANDSHAKE) {           
            int nextState = inspect_handshake(tcp_payload, data_end);
            if (nextState) {
                // handshake & login/status
                if (nextState == DISABLE_FILTER) {
                    __u64 now = bpf_ktime_get_ns();
                    bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
                    bpf_map_delete_elem(&conntrack_map, &flow_key);
                } else {
                    bpf_map_update_elem(&conntrack_map, &flow_key, &nextState, BPF_ANY);
                }
            } else {
                // invalid handshake drop
                if (++currentState > AWAIT_MC_HANDSHAKE + 3) {
                    bpf_map_delete_elem(&conntrack_map, &flow_key);
                } else {
                    bpf_map_update_elem(&conntrack_map, &flow_key, &currentState, BPF_ANY);    
                }
                return XDP_DROP;
            }   
        } else if (currentState == AWAIT_STATUS_REQUEST) {
            if(inspect_status_request(tcp_payload, data_end)) {
                bpf_map_update_elem(&conntrack_map, &flow_key, &AWAIT_PING, BPF_ANY);
            } else {
                bpf_map_delete_elem(&conntrack_map, &flow_key);
                return XDP_DROP;
            }
        } else if (currentState == AWAIT_PING) {
            bpf_map_delete_elem(&conntrack_map, &flow_key);
            if(!inspect_ping_request(tcp_payload, data_end)) {
                return XDP_DROP;
            }
        } else if (currentState == AWAIT_LOGIN) {
            bpf_map_delete_elem(&conntrack_map, &flow_key);
            if(!inspect_login_packet(tcp_payload, data_end)) {
                return XDP_DROP;
            }
            __u64 now = bpf_ktime_get_ns();
            bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
        } else {
            bpf_printk("%d SHOULD NOT HAPPEN\n", currentState);
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
