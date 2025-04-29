#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

// htons method you know
#define htons(x) ((uint16_t)((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8)))

// Minecraft server port
const uint16_t MINECRAFT_PORT = htons(25577);

// lru map update delay for connection tracking
const __u64 TIME_UPDATE = 1000000000;

// Definitions
// if defined signatures in login payloads are allowed (needed for 1.19 - 1.19.3 login)
// #define SIGNATURE_LOGIN
// if defines send a rst to the protected server to force close the connection.
#define INJECT_RESET

#ifdef SIGNATURE_LOGIN
    const int MAX_LOGIN_LEN = 2 + 1 + (16 * 3) + 1 + 8 + 512 + 2 + 4096 + 2;
#else
    const int MAX_LOGIN_LEN = 2 + 1 + (16 * 3) + 1 + 16;    
#endif

// PACKET LEN - PACKET ID - DATA
const int MIN_HANDSHAKE_LEN = 1 + 1 + 1 + 2 + 2 + 1;
const int MAX_HANDSHAKE_LEN = 2 + 1 + 5 + (255 * 3) + 2;
const int MIN_LOGIN_LEN = 1 + 1 + 2; // drop empty names instantly
const int PING_REQUEST_LEN = 10; // drop empty names instantly


// return code to indicate invalid packet length
const int INVALID_LEN = 200;
// return code to disable the filter for the connection
const int DISABLE_FILTER = 1000;

// STATE TRACKING
const __u8 AWAIT_ACK = 1;
const __u8 AWAIT_STATUS_REQUEST = 3;
const __u8 AWAIT_LOGIN = 4;
const __u8 AWAIT_PING = 5;
const __u8 AWAIT_MC_HANDSHAKE = 10; // counting this higher is alowed for counting invalid packets

// Connection tracking map (LRU) to track active flows (both TCP and UDP)
struct flow_key_t { __u64 key; };  // dummy struct to align 64-bit key if needed
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // flow 5-tuple key
    __type(value, __u8); // current state
    //__uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u64);   // flow 5-tuple key
    __type(value, __u64); // last seen timestamp (ns) or state info
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} player_connection_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);   // flow 5-tuple key
    __type(value, __u64); // last seen timestamp (ns) or state info
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");


// Parse TCP header (returns NULL if out-of-bounds)
static __always_inline struct tcphdr *parse_tcp(void *data_end, struct iphdr *ip) {
    struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + sizeof(struct iphdr));
    if ((void *)(tcp + 1) > data_end) {
        return NULL; // Packet not large enough for TCP header
    }
    return tcp;
}
// our key consists of src ip port and dst port
static __always_inline __u64 generate_flow_key(__u32 src_ip, __u16 src_port, __u16 dst_port) {
    __u64 key = 0;
    key |= (__u64)src_ip << 32;
    key |= (__u64)src_port << 16;
    key |= (__u64)dst_port;
    return key;
}

// Check for TCP bypass attempt via abnormal flags or state
static __always_inline int detect_tcp_bypass(struct tcphdr *tcp) {
    // Drop any packet with no control flags (NULL scan) or an unsolicited SYN-ACK
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) ||   // no SYN/ACK/FIN/RST flag
        (tcp->syn && tcp->ack) || // SYN+ACK from external (unexpected)
         tcp->urg) { // Drop if URG flag is set (rarely legitimate, often used in attacks to evade filters)                          
        return 1;
    }
    return 0;
}

// Read Minecraft varint
static __always_inline uint32_t read_varint_sized(signed char *start, signed char *end, int32_t *return_value, char max_size) {
    // i don't do loops in ebf
    if (max_size >= 1 && start + 1 <= end) {
        signed char first = start[0];
        if ((first & 0x80) != 0x80) {
            *return_value = first;
            return 1;
        } else {
            if (max_size >= 2 && start + 2 <= end) {
                signed char second = start[1];
                if ((second & 0x80) != 0x80) {
                    *return_value = (first & 0x7F) | ((second & 0x7F) << 7);
                    return 2;
                } else {
                    if (max_size >= 3 && start + 3 <= end) {
                        signed char third = start[2];
                        if ((third & 0x80) != 0x80) {
                            *return_value = (first & 0x7F) | ((second & 0x7F) << 7) | ((third & 0x7F) << 14);
                            return 3;
                        } else {
                            if (max_size >= 4 && start + 4 <= end) {
                                signed char fourth = start[3];
                                if ((fourth & 0x80) != 0x80) {
                                    *return_value = (first & 0x7F) | ((second & 0x7F) << 7) | ((third & 0x7F) << 14) | ((fourth & 0x7F) << 21);
                                    return 4;
                                } else {
                                    if (max_size >= 5 && start + 5 <= end) {
                                        signed char fifth = start[4];
                                        if ((fifth & 0x80) != 0x80) {
                                            *return_value = (first & 0x7F) | ((second & 0x7F) << 7) | ((third & 0x7F) << 14) | ((fourth & 0x7F) << 21) | ((fifth & 0x7F) << 28);
                                            return 5;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

// Helper method
static __always_inline uint32_t read_varint(signed char *start, signed char *end, int32_t *return_value) {
    return read_varint_sized(start, end, return_value, 5);
}

// Check for valid status request packet
static __always_inline int inspect_status_request(signed char *start, signed char *end) {
    return start + 2 <= end && start[0] == 1 && start[1] == 0;
}

// Check for valid login request packet
static __always_inline int inspect_login_packet(signed char *start, signed char *end) {
    __u32 size = end - start;
    if (size < MIN_LOGIN_LEN || size > MAX_LOGIN_LEN) return 0; 
    #ifndef SIGNATURE_LOGIN
        if (start + 2 <= end) { // second byte is packet id;
            if (start[1] != 0) { // packet id musst be 0;
                return 0;
            }
        } 
    #endif
    return 1;
}


// Check for valid handshake packet
// Note: it happens that the handshake and login or status request are in the same packet, 
// so we have to check for both cases here.
// this can also happen after retransmition.
static int inspect_handshake(signed char *start, signed char *end) {

    __u32 size = end - start;
    if (size > MAX_HANDSHAKE_LEN + MAX_LOGIN_LEN || size < MIN_HANDSHAKE_LEN) {
        return INVALID_LEN;
    }

    signed char *reader_index = start;
    int32_t packetLen;
    uint32_t position = read_varint(start, end, &packetLen);
    if (!position) {
        return 0;
    };
    reader_index += position;

    int32_t packetId;
    uint32_t packetIdIndex = read_varint(reader_index, end, &packetId);
    if (!packetIdIndex) {
        return 0;
    };
    reader_index += packetIdIndex;

    int32_t protocolVersion;
    uint32_t protocolVersionBytes = read_varint(reader_index, end, &protocolVersion);
    if (!protocolVersionBytes) {
        return 0;
    };
    reader_index += protocolVersionBytes;

    int32_t hostLen;
    uint32_t hostLenBytes = read_varint(reader_index, end, &hostLen);
    if (!hostLenBytes) {
        return 0;
    };

    if (hostLen > 255 || hostLen < 1) {
        return 0;
    }

    if (reader_index + hostLenBytes <= end) {
        reader_index += hostLenBytes;
        if (reader_index + hostLen <= end) {
            reader_index += hostLen;
            if (reader_index + 2 <= end) {
                uint16_t port = ((uint16_t*)reader_index)[0];
                reader_index += 2;
            } else {
                return 0;
            }
        }else {
            return 0;
        }
    } else {
        return 0;
    }


    int32_t intention;
    uint32_t intentionBytes = read_varint(reader_index, end, &intention);

    // we could check if the version as state 3 (transfer) but as BungeeCord ignores it i also do so for now
    if (!intentionBytes || (intention != 1 && intention != 2 && intention != 3)) {
        return 0;
    };
    reader_index += intentionBytes;

    // this packet contained exactly the handshake
    if (reader_index == end) {
        return intention == 1 ? AWAIT_STATUS_REQUEST : AWAIT_LOGIN;
    } 
    
    if (intention == 1) {
        // the packet also contained the staus request
        if (inspect_status_request(reader_index, end)) {
            return AWAIT_PING;
        }
    } else {
        if (inspect_login_packet(reader_index, end)) {
            // we received login here we have to disable the filter
            return DISABLE_FILTER;
        }
    }

    return 0;
}

static __always_inline int inspect_ping_request(signed char *start, signed char *end) {
    if (end - start != PING_REQUEST_LEN) return 0; 

    if (start[0] != 9) { // len
        return 0;
    }

    if (start + 1 < end) {
        if (start[1] != 1) { // packet id
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
    struct tcphdr *tcp = parse_tcp(data_end, ip);
    if (!tcp) {
        return XDP_ABORTED;
    }

    // Check if TCP destination port matches mc server port
    if (tcp->dest != MINECRAFT_PORT) {
        return XDP_PASS;  // not for our service
    }

    // Additional TCP bypass checks for abnormal flags
    if (detect_tcp_bypass(tcp)) {
        return XDP_DROP;
    }

    __u32 src_ip = ip->saddr;
    // __u32 dst_ip = ip->daddr;

    // Compute flow key for TCP connection
    __u64 flow_key = generate_flow_key(src_ip, tcp->source, tcp->dest);

    __u64 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked != NULL) {
        return XDP_DROP;
    }


    __u64 *lastTime = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (lastTime != NULL) {
        __u64 now = bpf_ktime_get_ns();
        if (*lastTime + TIME_UPDATE < now) {
            bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
        }
        return XDP_PASS;
    }


    __u8 *initial_connection_state_pointer = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    
    if (initial_connection_state_pointer == NULL) {
        if ((tcp->rst || tcp->fin) && !tcp->psh) { // let them close the connection, better for us
            return XDP_PASS;
        }
        if (tcp->syn) { // only check for syn flag here, we have checked abnormal flags in detect_tcp_bypass
            // it's a valid new SYN, create a new flow entry
            bpf_map_update_elem(&conntrack_map, &flow_key, &AWAIT_ACK, BPF_ANY);
            return XDP_PASS;
        }
        // if this is not a new SYN, it is out-of-state
        return XDP_DROP;
    } 

    __u8 currentState = *initial_connection_state_pointer;
    
    if (currentState == AWAIT_ACK) {
        if (tcp->ack) {
            bpf_map_update_elem(&conntrack_map, &flow_key, &AWAIT_MC_HANDSHAKE, BPF_ANY);
            currentState = AWAIT_MC_HANDSHAKE;
        } else {
            return XDP_DROP;
        }
    }


        bpf_printk("psh ack\n");

        signed char *tcp_payload = (signed char *)((__u8 *)tcp + (tcp->doff * 4));
        signed char *tcp_payload_end = (signed char *) data_end;
    
        if (tcp_payload < tcp_payload_end) {

            if (!tcp->psh || !tcp->ack) {
                __u64 now = bpf_ktime_get_ns();
                bpf_map_update_elem(&blocked_ips, &src_ip, &now, BPF_ANY);    
                bpf_map_delete_elem(&conntrack_map, &flow_key);
                #ifdef INJECT_RESET
                    tcp->rst = 1;
                    tcp->psh = 0;
                    tcp->ack = 0;
                    tcp->doff = 5;
                    return XDP_PASS;
                #else
                    return XDP_DROP;
                #endif
            }
            bpf_printk("tcp_payload < tcp_payload_end %d \n", currentState);
            if (currentState >= AWAIT_MC_HANDSHAKE) {           
                int nextState = inspect_handshake(tcp_payload, tcp_payload_end);
                // if the first packet has invalid length, we can block it
                // even with retransmition this len should always be valid‚
                if (nextState == INVALID_LEN) {
                    bpf_printk("invalid len\n");
                    __u64 now = bpf_ktime_get_ns();
                    bpf_map_update_elem(&blocked_ips, &src_ip, &now, BPF_ANY);    
                    bpf_map_delete_elem(&conntrack_map, &flow_key);
                    #ifdef INJECT_RESET
                        tcp->rst = 1;
                        tcp->psh = 0;
                        tcp->ack = 0;
                        tcp->doff = 5;
                        return XDP_PASS;
                    #else
                        return XDP_DROP;
                    #endif
                } else if (nextState) {
                    bpf_printk("valid!");
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
                        __u64 now = bpf_ktime_get_ns();
                        bpf_map_update_elem(&blocked_ips, &src_ip, &now, BPF_ANY);    
                        bpf_map_delete_elem(&conntrack_map, &flow_key);
                        #ifdef INJECT_RESET
                            tcp->rst = 1;
                            tcp->psh = 0;
                            tcp->ack = 0;
                            tcp->doff = 5;
                            return XDP_PASS;
                        #else
                            return XDP_DROP;
                        #endif
                    } else {
                        // allow a bit of retransmission, here it happens sometimes
                        bpf_map_update_elem(&conntrack_map, &flow_key, &currentState, BPF_ANY);    
                    }
                    return XDP_DROP;
                }   
            } else if (currentState == AWAIT_STATUS_REQUEST) {
                bpf_printk("status request\n");
                if(inspect_status_request(tcp_payload, tcp_payload_end)) {
                    bpf_map_update_elem(&conntrack_map, &flow_key, &AWAIT_PING, BPF_ANY);
                } else {
                    bpf_map_delete_elem(&conntrack_map, &flow_key);
                    return XDP_DROP;
                }
            } else if (currentState == AWAIT_PING) {
                bpf_printk("ping request\n");
                bpf_map_delete_elem(&conntrack_map, &flow_key);
                if(!inspect_ping_request(tcp_payload, tcp_payload_end)) {
                    return XDP_DROP;
                }
            } else if (currentState == AWAIT_LOGIN) {
                bpf_printk("login request\n");
                bpf_map_delete_elem(&conntrack_map, &flow_key);
                if(!inspect_login_packet(tcp_payload, tcp_payload_end)) {
                    return XDP_DROP;
                }
                __u64 now = bpf_ktime_get_ns();
                bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
            } else {
                bpf_printk("NAHHHH\n");
            }
        }

    
    return XDP_PASS;
}

//char _license[] SEC("license") = "Proprietary";
char _license[] SEC("license") = "GPL";
