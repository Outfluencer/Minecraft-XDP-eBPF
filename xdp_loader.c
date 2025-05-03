#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "embedded_data.h"

static int if_idx = 0;

void sigint_handler(int sig) {
    printf("\nCaught signal %d (Ctrl+C). Exiting gracefully...\n", sig);
    if (if_idx) {
        bpf_xdp_detach(if_idx, 0, NULL);
    }
    exit(0);
}

static struct bpf_object *bpf_obj;

int main(int argc, char **argv) 
{
    if (argc < 2) {
        printf("Usage: %s <network interface>\n", argv[0]);
        return 1;
    }

    if (signal(SIGINT, sigint_handler) == SIG_ERR && signal(9, sigint_handler) == SIG_ERR) {
        perror("Unable to set signal handler");
        return 1;
    }

    const char *interface = argv[1];
    bpf_obj = bpf_object__open_mem(&minecraft_filter_o, minecraft_filter_o_len, NULL);

    if (!bpf_obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    int err = bpf_object__load(bpf_obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object file: %i\n", err);
        bpf_object__close(bpf_obj);
        return 1;
    }

    int interface_idx = if_nametoindex(interface);
    struct bpf_program *prog = bpf_object__find_program_by_name(bpf_obj, "minecraft_filter");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(bpf_obj);
        return 1;
    }

    int program_fd = bpf_program__fd(prog);
    int attached_fd = bpf_xdp_attach(interface_idx, program_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);

    if (attached_fd < 0) {
        fprintf(stderr, "Failed to attach BPF program to interface %s\n", interface);
        bpf_object__close(bpf_obj);
        return 1;
    }
    if_idx = interface_idx;

    printf("BPF program attached to interface %s\n", interface);
    printf("Program FD: %i\n", program_fd);
    printf("Attached FD: %i\n", attached_fd);

    int connection_map_fd = bpf_obj_get("/sys/fs/bpf/player_connection_map");
    if (connection_map_fd < 0) {
        perror("bpf_obj_get /sys/fs/bpf/player_connection_map");
        sigint_handler(1);
        return 1;
    }
    printf("connection_map_fd: %i\n", connection_map_fd);

    int blocked_ips_map_fd = bpf_obj_get("/sys/fs/bpf/blocked_ips");
    if (blocked_ips_map_fd < 0) {
        perror("bpf_obj_get /sys/fs/bpf/blocked_ips");
        sigint_handler(1);
        return 1;
    }
    printf("blocked_ips_map_fd: %i\n", blocked_ips_map_fd);

    while(1) {
        // Get the current time in nanoseconds since boot
        // the bpf nano time works the same
        struct timespec ts;
        clock_gettime(CLOCK_BOOTTIME, &ts);
        uint64_t now = (uint64_t)ts.tv_sec * 1000000000L + ts.tv_nsec;

        {
            __u64 key = 0;
            __u64 next_key;
            __u64 last_connection_update;
            int removed_count = 0;
            printf("start removing old connections\n");
            while (bpf_map_get_next_key(connection_map_fd, &key, &next_key) == 0) {
                if (bpf_map_lookup_elem(connection_map_fd, &next_key, &last_connection_update) == 0) {
                    // timed out
                    if (last_connection_update + ( 1000000000L * 45 ) < now ) {
                        removed_count++;
                        bpf_map_delete_elem(connection_map_fd, &next_key);
                    }
                } else {
                    break;
                }
                key = next_key;
            }
            printf("removed %i old connections\n", removed_count);
        }
        

        {
            __u64 key = 0;
            __u64 next_key;
            __u64 block_time;
            int removed_count = 0;
            printf("start removing old connection blocks\n");
            while (bpf_map_get_next_key(blocked_ips_map_fd, &key, &next_key) == 0) {
                if (bpf_map_lookup_elem(blocked_ips_map_fd, &next_key, &block_time) == 0) {
                    // remove block
                    if (block_time + ( 1000000000L * 60 ) < now ) {
                        removed_count++;
                        bpf_map_delete_elem(blocked_ips_map_fd, &next_key);
                    }
                } else {
                    break;
                }
                key = next_key;
            }
            printf("removed blocks of %i connections\n", removed_count);
        }
        
        sleep(15);
    }
}