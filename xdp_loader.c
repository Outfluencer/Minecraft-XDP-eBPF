#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "embedded_data.h"
#include <dlfcn.h>
#include "common.h"
#include <pthread.h>

#define OLD_CONNECTION_TIMEOUT 60
#define BLOCKED_IP_TIMEOUT 60
#define THROTTLE_CLEAR_CYCLE 3


static void *bpf_obj;
static int if_idx, connection_map_fd, blocked_ips_map_fd, throttle_ips_map_fd;
static volatile int running = 1;
static pthread_t worker_threads[3];

typedef int (*bpf_set_link_xdp_fd_fn)(int, int, __u32);
typedef int (*bpf_xdp_attach_fn)(int, int, __u32, void *);
typedef int (*bpf_xdp_detach_fn)(int, __u32, void *);
typedef int (*bpf_obj_get_fn)(const char *pathname);
typedef int (*bpf_object__close_fn)(void *obj);
typedef int (*bpf_object__load_fn)(void *obj);
typedef void* (*bpf_object__open_mem_fn)(const void *buf, size_t buf_len, size_t ignore);
typedef int (*bpf_program__fd_fn)(void *prog);
typedef void* (*bpf_object__find_program_by_name_fn)(void *obj, const char *name);
typedef int (*bpf_map_get_next_key_fn)(int fd, const void *key, void *next_key);
typedef int (*bpf_map_lookup_elem_fn)(int fd, const void *key, void *value);
typedef int (*bpf_map_delete_elem_fn)(int fd, const void *key);

static bpf_set_link_xdp_fd_fn legacy_attach = NULL;
static bpf_xdp_attach_fn modern_attach = NULL;
static bpf_xdp_detach_fn modern_detach = NULL;
static bpf_obj_get_fn bpf_obj_get = NULL;
static bpf_object__close_fn bpf_object__close = NULL;
static bpf_object__load_fn bpf_object__load = NULL;
static bpf_object__open_mem_fn bpf_object__open_mem = NULL;
static bpf_program__fd_fn bpf_program__fd = NULL;
static bpf_object__find_program_by_name_fn bpf_object__find_program_by_name = NULL;
static bpf_map_get_next_key_fn bpf_map_get_next_key = NULL;
static bpf_map_lookup_elem_fn bpf_map_lookup_elem = NULL;
static bpf_map_delete_elem_fn bpf_map_delete_elem = NULL;

static int resolve_libbpf_symbols() {
    void *handle = dlopen("libbpf.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "libbpf.so not found: %s\n", dlerror());
        return 0;
    }

    legacy_attach = (bpf_set_link_xdp_fd_fn)dlsym(handle, "bpf_set_link_xdp_fd");
    modern_attach = (bpf_xdp_attach_fn)dlsym(handle, "bpf_xdp_attach");
    modern_detach = (bpf_xdp_detach_fn)dlsym(handle, "bpf_xdp_detach");

    bpf_obj_get = (bpf_obj_get_fn)dlsym(handle, "bpf_obj_get");
    bpf_object__close = (bpf_object__close_fn)dlsym(handle, "bpf_object__close");
    bpf_object__load = (bpf_object__load_fn)dlsym(handle, "bpf_object__load");
    bpf_object__open_mem = (bpf_object__open_mem_fn)dlsym(handle, "bpf_object__open_mem");
    bpf_program__fd = (bpf_program__fd_fn)dlsym(handle, "bpf_program__fd");
    bpf_object__find_program_by_name = (bpf_object__find_program_by_name_fn)dlsym(handle, "bpf_object__find_program_by_name");
    bpf_map_get_next_key = (bpf_map_get_next_key_fn)dlsym(handle, "bpf_map_get_next_key");
    bpf_map_lookup_elem = (bpf_map_lookup_elem_fn)dlsym(handle, "bpf_map_lookup_elem");
    bpf_map_delete_elem = (bpf_map_delete_elem_fn)dlsym(handle, "bpf_map_delete_elem");

    if (!bpf_obj_get || !bpf_object__close || !bpf_object__load || !bpf_object__open_mem || !bpf_program__fd || !bpf_object__find_program_by_name || !bpf_map_get_next_key || !bpf_map_lookup_elem || !bpf_map_delete_elem) {
        fprintf(stderr, "Failed to resolve libbpf methods\n");
        return 0;
    }
    if(legacy_attach) {
        printf("Use bpf_set_link_xdp_fd to attach and detach xbf\n");
    } else {
        if(modern_attach) {
            printf("Use bpf_xdp_attach to attach xbf\n");
        }
        if (modern_detach){
            printf("Use bpf_xdp_detach to detach xbf\n");
        }
    }

    if (!legacy_attach && (!modern_attach&& !modern_detach)) {
        return 0;
    }

    return 1;
}

void sigint_handler(int sig) {
    if(!running) {
        return;
    }

    running = 0;

    printf("\nCaught signal %d. Exiting gracefully...\n", sig);
    if(bpf_obj) {
        bpf_object__close(bpf_obj);
    }
    if (if_idx) {
        if (legacy_attach) {
            legacy_attach(if_idx, -1, 0);
        } else {
            modern_detach(if_idx, 0, NULL);
        }
    }
}

void* clear_throttle(void *arg) {
    __u64 ticks = 0;
    while(running) {
        if (++ticks % THROTTLE_CLEAR_CYCLE == 0) {
            __u32 key;
            __u32 next_key;
            __u32 count;
            int removed_count = 0;
            if (bpf_map_get_next_key(throttle_ips_map_fd, NULL, &key) == 0) {
                while (1) {
                    int has_next = bpf_map_get_next_key(throttle_ips_map_fd, &key, &next_key);
                    if (bpf_map_lookup_elem(throttle_ips_map_fd, &key, &count) == 0) {
                        bpf_map_delete_elem(throttle_ips_map_fd, &key);
                        removed_count++;           
                    }
                    if (has_next != 0) {
                        break;
                    }
                    key = next_key;
                }
                if (removed_count > 0) {
                    printf("removed %i ip throttles\n", removed_count);
                }
            }  
        }
        sleep(1);
    }
    printf("Closed clear old connection thread\n");
    return NULL;
}

void* clear_old_connections(void *arg) {
    __u64 ticks = 0;
    while(running) {
        if (++ticks % OLD_CONNECTION_TIMEOUT == 0) {
            // Get the current time in nanoseconds since boot
            // the bpf nano time works the same
            struct timespec ts;
            clock_gettime(CLOCK_BOOTTIME, &ts);
            __u64 now = (__u64)ts.tv_sec * SECOND_TO_NANOS + ts.tv_nsec;
            struct ipv4_flow_key key;
            struct ipv4_flow_key next_key;
            __u64 last_connection_update;
            int removed_count = 0;

            // Get the first key using NULL
            if (bpf_map_get_next_key(connection_map_fd, NULL, &key) == 0) {
                while (1) {
                    int has_next = bpf_map_get_next_key(connection_map_fd, &key, &next_key);
                    if (bpf_map_lookup_elem(connection_map_fd, &key, &last_connection_update) == 0) {
                        if (last_connection_update + (SECOND_TO_NANOS * OLD_CONNECTION_TIMEOUT) < now) {
                            removed_count++;
                            bpf_map_delete_elem(connection_map_fd, &key);
                        }                
                    }
                    if (has_next != 0) {
                        break;
                    }
                    key = next_key;
                }

                if (removed_count > 0) {
                    printf("removed %i old connections\n", removed_count);
                }
            }       
        }
        sleep(1);
    }
    printf("Closed clear old connection thread\n");
    return NULL;
}

void* clear_blocked_ips(void *arg) {
    __u64 ticks = 0;
    while(running) {
        if (++ticks % BLOCKED_IP_TIMEOUT == 0) {

            struct timespec ts;
            clock_gettime(CLOCK_BOOTTIME, &ts);
            __u64 now = (__u64)ts.tv_sec * SECOND_TO_NANOS + ts.tv_nsec;

            __u32 key;
            __u32 next_key;
            __u64 block_time;
            int removed_count = 0;
            // Get the first key using NULL
            if (bpf_map_get_next_key(blocked_ips_map_fd, NULL, &key) == 0) {
                while (1) {
                    int has_next = bpf_map_get_next_key(blocked_ips_map_fd, &key, &next_key);
                    if (bpf_map_lookup_elem(blocked_ips_map_fd, &key, &block_time) == 0) {
                        if (block_time + (SECOND_TO_NANOS * BLOCKED_IP_TIMEOUT) < now) {
                            removed_count++;
                            bpf_map_delete_elem(blocked_ips_map_fd, &key);
                        }                
                    }
                    if (has_next != 0) {
                        break;
                    }
                    key = next_key;
                }
    
                if (removed_count > 0) {
                    printf("removed %i blocked ips\n", removed_count);
                }
            }
        }
        sleep(1);
    }
    printf("Closed clear old blockd ipv4 thread\n");
    return NULL;
}

int main(int argc, char **argv) 
{
    if (argc < 2) {
        printf("Usage: %s <network interface>\n", argv[0]);
        return 1;
    }

    printf("Loading minecraft xdp filter v1.3.1 by Outfluencer...\n");

    if (signal(SIGINT, sigint_handler) == SIG_ERR && signal(SIGTERM, sigint_handler) == SIG_ERR && signal(SIGSEGV, sigint_handler) == SIG_ERR) {
        perror("Unable to set signal handler");
        return 1;
    }

    if (!resolve_libbpf_symbols()) {
        fprintf(stderr, "No way found to load xbf\n");
        return 1;
    }

    const char *interface = argv[1];
    bpf_obj = bpf_object__open_mem(&minecraft_filter_o, minecraft_filter_o_len, 0);

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
    if (interface_idx == 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", interface);
        bpf_object__close(bpf_obj);
        return 1;
    }

    void* prog = bpf_object__find_program_by_name(bpf_obj, "minecraft_filter");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(bpf_obj);
        return 1;
    }

    int program_fd = bpf_program__fd(prog);
    if (program_fd < 0) {
        fprintf(stderr, "Failed to get BPF program FD\n");
        bpf_object__close(bpf_obj);
        return 1;
    }
    int attached = 0;

    if(legacy_attach) {
        printf("Attaching using legacy XDP API...\n");
        attached = legacy_attach(interface_idx, program_fd, XDP_FLAGS_UPDATE_IF_NOEXIST); //bpf_xdp_attach(interface_idx, program_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    } else {
        printf("Attaching using modern XDP API...\n");
        attached = modern_attach(interface_idx, program_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    }

    if (attached < 0) {
        fprintf(stderr, "Failed to attach BPF program to interface %s\n", interface);
        bpf_object__close(bpf_obj);
        return 1;
    }
    if_idx = interface_idx;

    printf("BPF program attached to interface %s\n", interface);
    printf("Program FD: %i\n", program_fd);

    connection_map_fd = bpf_obj_get("/sys/fs/bpf/player_connection_map");
    if (connection_map_fd < 0) {
        perror("Failed to load /sys/fs/bpf/player_connection_map\n");
        sigint_handler(1);
        return 1;
    }

    blocked_ips_map_fd = bpf_obj_get("/sys/fs/bpf/blocked_ips");
    if (blocked_ips_map_fd < 0) {
        perror("Failed to load /sys/fs/bpf/blocked_ips\n");
        sigint_handler(1);
        return 1;
    }
    throttle_ips_map_fd = bpf_obj_get("/sys/fs/bpf/connection_throttle");
    if (throttle_ips_map_fd < 0) {
        perror("Failed to load /sys/fs/bpf/connection_throttle\n");
        sigint_handler(1);
        return 1;
    }

    if(pthread_create(&worker_threads[0], NULL, &clear_blocked_ips, NULL)) {
        perror("Failed to create clear_blocked_ips thread\n");
        sigint_handler(1);
        return 1;
    }

    if(pthread_create(&worker_threads[1], NULL, &clear_old_connections, NULL)) {
        perror("Failed to create clear_old_connections thread\n");
        sigint_handler(1);
        return 1;
    }
    if(pthread_create(&worker_threads[2], NULL, &clear_throttle, NULL)) {
        perror("Failed to create clear_throttle thread\n");
        sigint_handler(1);
        return 1;
    }

    pthread_join(worker_threads[0], NULL);
    pthread_join(worker_threads[1], NULL);
    pthread_join(worker_threads[2], NULL);
    printf("Have a nice day\n");
}