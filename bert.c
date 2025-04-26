#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
// *** Configuration Constants ***  
#define htons(x) ((uint16_t)((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8)))


const __u8 REQUIRES_SYN = 0;
const __u8 RECEIVED_SYN = 1;
const __u8 TCP_ESTABLISHED = 2;
const __u8 MOTD = 3;
const __u8 LOGIN = 4;
const __u8 PING = 5;
const __u8 FINISHED = 200;

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

static __always_inline int inspect_handshake(void *data, void *data_end) {
    __u8 *start = (__u8 *)data;
    __u8 *end = (__u8 *)data_end;
    __u32 size = end - start;
    if (size > 774 || size < 6) return 0;
    __u8 *last_byte_ptr = start + (size - 1);

    int intention = 0;
    if (last_byte_ptr + 1 <= end) {
        intention = *last_byte_ptr;
    }

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

                packetLen = (byte & 0x7F) | (byte2 << 7);
                if ((size - 2) != packetLen) {
                    // fuck that connection again
                    return 0;
                }
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
            packetLen = byte;
            if ((size - 1) != packetLen) {
                // fuck that connection again
                return 0;
            }
            position = 2;
	    }
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
   return intention;
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

static __always_inline int inspect_login_request(void *data, void *data_end) {
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

static __always_inline int inspect_ping_request(void *data, void *data_end) {
    __u8 *start = (__u8 *)data;
    __u8 *end = (__u8 *)data_end;
    __u32 size = end - start;
    if (size != 10) return 0; 

    if (start < end) {
        if (*(signed char *)(start) != 9) { // len
            return 0;
        }
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

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // Prepare a flow key for tracking (we'll fill it based on protocol below)
    // Parse TCP header
    struct tcphdr *tcp = parse_tcp(data, data_end, ip);
    if (!tcp) {
        return XDP_ABORTED;
    }
    // Check if TCP destination port matches FiveM server port
    if (tcp->dest != htons(25577)) {
        return XDP_PASS;  // not for our service
    }

    // Additional TCP bypass checks for abnormal flags
    if (detect_tcp_bypass(tcp)) {
        return XDP_DROP;
    }

    // Compute flow key for TCP connection
    __u64 flow_key = generate_flow_key(src_ip, dst_ip, tcp->source, tcp->dest, IPPROTO_TCP);

    __u64 *lastTime = NULL;
    lastTime = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (lastTime != NULL) {
        __u64 now = bpf_ktime_get_ns();
        if (*lastTime + 1000000000 < now) {
            bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
        }
        return XDP_PASS;
    }


    __u8 *initial_connection_state = NULL;
    initial_connection_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    uint8_t checkPayload = 1;
    
    if (initial_connection_state == NULL) {
        // No entry found: if this is not a new SYN, it's an out-of-state packet -> drop
        
        if (tcp->rst || tcp->fin) { // let them close the connection, better for us
            return XDP_PASS;
        }

        if (tcp->syn && !tcp->ack) {
            // Otherwise, it's a valid new SYN, create a new flow entry
            bpf_map_update_elem(&conntrack_map, &flow_key, &RECEIVED_SYN, BPF_ANY);
            checkPayload = 0;
        } else {
            return XDP_DROP;
        }
    } else if (*initial_connection_state == RECEIVED_SYN) {
        if (!tcp->ack) {
            return XDP_DROP;
        }
        bpf_map_update_elem(&conntrack_map, &flow_key, &TCP_ESTABLISHED, BPF_ANY);
	    *initial_connection_state = TCP_ESTABLISHED;	
    }

    if (checkPayload) {
        // Deep Packet Inspection for TCP payload
        void *tcp_payload = (void *)((__u8 *)tcp + (tcp->doff * 4));
        if (tcp_payload < data_end) {  // there is payload (doff is header length in 32-bit words)
            if (*initial_connection_state == TCP_ESTABLISHED) {
                int requestedProtocol = inspect_handshake(tcp_payload, data_end);
                if (requestedProtocol == 1) {
                    //bpf_printk("%llu STATUS HANDSHAKE\n", flow_key);
                    bpf_map_update_elem(&conntrack_map, &flow_key, &MOTD, BPF_ANY);
                } else if (requestedProtocol == 2 || requestedProtocol == 3) {
                    //bpf_printk("%llu LOGIN HANDSHAKE\n", flow_key);
                    bpf_map_update_elem(&conntrack_map, &flow_key, &LOGIN, BPF_ANY);
                } else {
                    //bpf_printk("%llu INVALID HANDSHAKE\n", flow_key);
                    bpf_map_delete_elem(&conntrack_map, &flow_key);
                    return XDP_DROP;
                }       
            } else if (*initial_connection_state == MOTD) {
                if(inspect_status_request(tcp_payload, data_end)) {
                   // bpf_printk("%llu STATUS REQUEST\n", flow_key);
                    bpf_map_update_elem(&conntrack_map, &flow_key, &PING, BPF_ANY);
                } else {
                    //bpf_printk("%llu INVALID STATUS REQUEST\n", flow_key);
                    bpf_map_delete_elem(&conntrack_map, &flow_key);
                    return XDP_DROP;
                }
            } else if (*initial_connection_state == PING) {
                if(inspect_ping_request(tcp_payload, data_end)) {
                    //bpf_printk("%llu PING REQUEST\n", flow_key);
                    //bpf_map_update_elem(&conntrack_map, &flow_key, &FINISHED, BPF_ANY);
                    // we can close the connection here
                    bpf_map_delete_elem(&conntrack_map, &flow_key);
                } else {
                    //bpf_printk("%llu INVALID PING REQUEST\n", flow_key);
                    bpf_map_delete_elem(&conntrack_map, &flow_key);
                    return XDP_DROP;
                }
            } else if (*initial_connection_state == LOGIN) {
                //bpf_printk("%llu LOGIN REQUEST\n", flow_key);
                __u64 now = bpf_ktime_get_ns();
                bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
                bpf_map_delete_elem(&conntrack_map, &flow_key);
            }

        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
