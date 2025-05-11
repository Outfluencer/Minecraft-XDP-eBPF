#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include "common.h"

// htons method you know
#define htons(x) ((uint16_t)((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8)))

// Minecraft server port
const uint16_t MINECRAFT_PORT = htons(25565);

// if defines send a rst to the protected server to force close the connection.
#define INJECT_RESET

static __always_inline int drop_or_rst(struct tcphdr *tcp) {
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

// length pre checks
const int MIN_HANDSHAKE_LEN = 1 + 1 + 1 + 2 + 2 + 1;
const int MAX_HANDSHAKE_LEN = 2 + 1 + 5 + (255 * 3) + 2;
const int MIN_LOGIN_LEN = 1 + 1 + 2; // drop empty names instantly
const int PING_REQUEST_LEN = 10; // drop empty names instantly
const int MAX_LOGIN_LEN = 2 + 1 + (16 * 3) + 1 + 8 + 512 + 2 + 4096 + 2; // len, packetid, name, profilekey, uuid

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_flow_key);
    __type(value, struct initial_state); 
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct ipv4_flow_key); 
    __type(value, __u64); // last seen timestamp
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} player_connection_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);   // ipv4 address (4 bytes)
    __type(value, __u64); // blocked at time
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

static __always_inline int detect_tcp_bypass(struct tcphdr *tcp) {
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) ||   // no SYN/ACK/FIN/RST flag
        (tcp->syn && tcp->ack) || // SYN+ACK from external (unexpected)
         tcp->urg) { // Drop if URG flag is set                     
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
        } else if (max_size >= 2 && start + 2 <= end) {
            signed char second = start[1];
            if ((second & 0x80) != 0x80) {
                *return_value = (first & 0x7F) | ((second & 0x7F) << 7);
                return 2;
            } else if (max_size >= 3 && start + 3 <= end) {
                signed char third = start[2];
                if ((third & 0x80) != 0x80) {
                    *return_value = (first & 0x7F) | ((second & 0x7F) << 7) | ((third & 0x7F) << 14);
                    return 3;
                } else if (max_size >= 4 && start + 4 <= end) {
                    signed char fourth = start[3];
                    if ((fourth & 0x80) != 0x80) {
                        *return_value = (first & 0x7F) | ((second & 0x7F) << 7) | ((third & 0x7F) << 14) | ((fourth & 0x7F) << 21);
                        return 4;
                    } else if (max_size >= 5 && start + 5 <= end) {
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
// see https://github.com/SpigotMC/BungeeCord/blob/master/protocol/src/main/java/net/md_5/bungee/protocol/packet/LoginRequest.java
static __always_inline int inspect_login_packet(signed char *start, signed char *end, int protocol_version) {
    __u32 size = end - start;
    if (size < MIN_LOGIN_LEN || size > MAX_LOGIN_LEN) return 0; 

    signed char *reader_index = start;
    int32_t packet_len;
    uint32_t packet_len_bytes = read_varint_sized(start, end, &packet_len, 2);
    if (!packet_len_bytes || packet_len > MAX_LOGIN_LEN) {
        return 0;
    };
    reader_index += packet_len_bytes;

    int32_t packet_id;
    uint32_t packet_id_bytes = read_varint_sized(reader_index, end, &packet_id, 1);
    if (!packet_id_bytes || packet_id != 0x00) {
        return 0;
    };
    reader_index += packet_id_bytes;

    int32_t name_len;
    uint32_t name_len_bytes = read_varint_sized(reader_index, end, &name_len, 2);
    if (!name_len_bytes) {
        return 0;
    };
    if (name_len > 16 * 3 || name_len < 1) {
        return 0;
    }

    if (reader_index + name_len_bytes <= end) {
        reader_index += name_len_bytes;
        if (reader_index + name_len <= end) {
            reader_index += name_len;
            // 1_19                                          1_19_3
            if (protocol_version >= 759 && protocol_version < 761) {
                if (reader_index + 1 <= end) {
                    char has_public_key = reader_index[0];
                    reader_index++;
                    if (has_public_key) {
                        if (reader_index + 8 <= end) {
                            reader_index += 8; // skip expiry time
                            int32_t key_len;
                            uint32_t key_len_bytes = read_varint_sized(reader_index, end, &key_len, 2);

                            // i hate this bpf verfier );, we can't merge this if's together
                            if (!key_len_bytes) {
                                return 0;
                            };
                            if (key_len < 0 || key_len > 512) {
                                return 0;
                            }
    
                            if (reader_index + key_len_bytes <= end) {
                                reader_index += key_len_bytes;
                                if (key_len >= 0 && reader_index + key_len <= end) {
                                    reader_index += key_len;
                                    int32_t signaturey_len;
                                    uint32_t signaturey_len_bytes = read_varint_sized(reader_index, end, &signaturey_len, 2);

                                    // i hate this bpf verfier );, we can't merge this if's together
                                    if (!signaturey_len_bytes) {
                                        return 0;
                                    };
                                    if (signaturey_len < 0 || signaturey_len > 4096) {
                                        return 0;
                                    }
                                    
                                    if (reader_index + signaturey_len_bytes <= end) {
                                        reader_index += signaturey_len_bytes;
                                        if (reader_index + signaturey_len <= end) {
                                            reader_index += signaturey_len;
                                        }
                                    } else {
                                        return 0;
                                    }
                                }else {
                                    return 0;
                                }
                            } else {
                                return 0;
                            }
                        } else {
                            return 0;
                        }
                    }
                } else {
                    return 0;
                }
            }
            //  1_19_1
            if (protocol_version >= 760) {
                // 1_20_2
                if (protocol_version >= 764) {
                    // check space for uuid
                    if (reader_index + 16 <= end) {
                        reader_index += 16;
                    } else {
                        return 0;
                    }
                } else {
                    // check space for uuid and boolean
                    if (reader_index + 1 <= end) {
                        char has_uuid = reader_index[0];
                        reader_index++;
                        if(has_uuid) {
                            if (reader_index + 16 <= end) {
                                reader_index += 16;
                            } else {
                                return 0;
                            }
                        }
                    } else {
                        return 0;
                    }
                }
            }
        }else {
            return 0;
        }
    } else {
        return 0;
    }

    // no data left to read, this is a valid login packet
    return reader_index == end;
}


// Check for valid handshake packet
// Note: it happens that the handshake and login or status request are in the same packet, 
// so we have to check for both cases here.
// this can also happen after retransmition.
// see https://github.com/SpigotMC/BungeeCord/blob/master/protocol/src/main/java/net/md_5/bungee/protocol/packet/Handshake.java
static int inspect_handshake(signed char *start, signed char *end, int *protocol_version, __u16 tcp_dest) {

    __u32 size = end - start;

    if (start + 1 <= end) {
        if (start[0] == (signed char)0xFE) {
            return RECEIVED_LEGACY_PING;
        }
    }

    if (size > MAX_HANDSHAKE_LEN + MAX_LOGIN_LEN || size < MIN_HANDSHAKE_LEN) {
        return 0;
    }

    signed char *reader_index = start;
    int32_t packet_len;
    uint32_t packet_len_bytes = read_varint_sized(start, end, &packet_len, 2);
    if (!packet_len_bytes || packet_len > MAX_HANDSHAKE_LEN) {
        return 0;
    };
    reader_index += packet_len_bytes;

    int32_t packet_id;
    uint32_t packet_id_bytes = read_varint_sized(reader_index, end, &packet_id, 1);
    if (!packet_id_bytes || packet_id != 0x00) {
        return 0;
    };
    reader_index += packet_id_bytes;

    uint32_t protocol_version_bytes = read_varint_sized(reader_index, end, protocol_version, 5);
    if (!protocol_version_bytes) {
        return 0;
    };
    reader_index += protocol_version_bytes;

    int32_t host_len;
    uint32_t host_len_bytes = read_varint_sized(reader_index, end, &host_len, 2);
    if (!host_len_bytes) {
        return 0;
    };

    if (host_len > 255 * 3 || host_len < 1) {
        return 0;
    }

    if (reader_index + host_len_bytes <= end) {
        reader_index += host_len_bytes;
        if (reader_index + host_len <= end) {
            reader_index += host_len;
            if (reader_index + 2 <= end) {
                // __u16 port = ((__u16*)reader_index)[0];
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
    uint32_t intention_bytes = read_varint_sized(reader_index, end, &intention, 1);

    // we could check if the version as state 3 (transfer) but as BungeeCord ignores it i also do so for now
    if (!intention_bytes || (intention != 1 && intention != 2 && (*protocol_version >= 766 ? intention != 3 : 1))) {
        return 0;
    };
    reader_index += intention_bytes;

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
        if (inspect_login_packet(reader_index, end, *protocol_version)) {
            // we received login here we have to disable the filter
            return LOGIN_FINISHED;
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

static __always_inline int retransmission(struct initial_state *initial_state, __u32 *src_ip, struct ipv4_flow_key *flow_key, struct tcphdr *tcp) {
    if (++initial_state->fails > MAX_RETRANSMISSION) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&blocked_ips, &src_ip, &now, BPF_ANY);    
        bpf_map_delete_elem(&conntrack_map, &flow_key);
        return drop_or_rst(tcp);
    }

    bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_ANY);    
    return XDP_DROP;
}

SEC("xdp")
int minecraft_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_ABORTED;
    }

    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5) {
        return XDP_ABORTED;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return XDP_ABORTED;
    }

    if (tcp->doff < 5) {
        return XDP_ABORTED;
    }
    
    __u32 tcp_hdr_len = tcp->doff * 4;
    if ((void *)tcp + tcp_hdr_len > data_end) {
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
    // Compute flow key for TCP connection
    struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);


    __u64 *lastTime = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (lastTime != NULL) {
        __u64 now = bpf_ktime_get_ns();
        if (*lastTime + SECOND_TO_NANOS < now) {
            bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
        }
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    
    if (initial_state == NULL) {
        if (!tcp->syn) {
            return XDP_DROP;
        }

        // drop syn's of new connections if blocked
        __u64 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (blocked != NULL) {
            return XDP_DROP;
        }

        // it's a valid new SYN, create a new flow entry
        struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0);
        bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY);
        return XDP_PASS;
    } 

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK) {
        if (!tcp->ack) {
            return XDP_DROP;
        }
        initial_state->state = state = AWAIT_MC_HANDSHAKE;
        bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_ANY);
    }

    signed char *tcp_payload = (signed char *)((__u8 *)tcp + (tcp->doff * 4));
    signed char *tcp_payload_end = (signed char *) data_end;

    if (tcp_payload < tcp_payload_end) {

        if (!tcp->ack) {
            // drop the connection
            bpf_map_delete_elem(&conntrack_map, &flow_key);
            return drop_or_rst(tcp);
        }

        if (state == AWAIT_MC_HANDSHAKE) {
            int protocol_version = 0;
            int next_state = inspect_handshake(tcp_payload, tcp_payload_end, &protocol_version, tcp->dest);
            // if the first packet has invalid length, we can block it
            // even with retransmition this len should always be valid‚
            if (!next_state) {
                return retransmission(initial_state, &src_ip, &flow_key, tcp);
            }

            if (next_state == RECEIVED_LEGACY_PING) { // fully drop legacy ping
                bpf_map_delete_elem(&conntrack_map, &flow_key);
                return drop_or_rst(tcp);
            }

            initial_state->state = next_state;
            initial_state->protocol = protocol_version;

            // handshake & login/status
            if (next_state == LOGIN_FINISHED) {
                __u64 now = bpf_ktime_get_ns();
                bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
                bpf_map_delete_elem(&conntrack_map, &flow_key);
            } else {
                bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_ANY);
            }
        } else if (state == AWAIT_STATUS_REQUEST) {
            if(!inspect_status_request(tcp_payload, tcp_payload_end)) {
                return retransmission(initial_state, &src_ip, &flow_key, tcp);
            }
            initial_state->state = AWAIT_PING;
            bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_ANY);
        } else if (state == AWAIT_PING) {
            if(!inspect_ping_request(tcp_payload, tcp_payload_end)) {
                return retransmission(initial_state, &src_ip, &flow_key, tcp);
            }
            initial_state->state = PING_COMPLETE;
            bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_ANY);
        } else if (state == AWAIT_LOGIN) {
            if(!inspect_login_packet(tcp_payload, tcp_payload_end, initial_state->protocol)) {
                return retransmission(initial_state, &src_ip, &flow_key, tcp);
            }
            __u64 now = bpf_ktime_get_ns();
            bpf_map_update_elem(&player_connection_map, &flow_key, &now, BPF_ANY);
            bpf_map_delete_elem(&conntrack_map, &flow_key);
        } else if (state == PING_COMPLETE) {
            bpf_map_delete_elem(&conntrack_map, &flow_key);
            return drop_or_rst(tcp);
        } else {
            // should never happen
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Proprietary";
