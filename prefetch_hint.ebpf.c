#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "params.h"

struct least_hot_bin {
    char name[MAX_FILENAME_LENGTH];
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, char[MAX_FILENAME_LENGTH]);
    __type(value, __u64);
} bin_freq_map SEC(".maps");

__u64 unique_bins_count = 0;

static __always_inline __u8 str_cmp(const char *s1, __u16 size, const char *s2)
{
    int i;
    #pragma unroll
    for (i = 0; i < size; i++) {
        if (s1[i] != s2[i])
            return 1;
        if (i == size - 1)
            return 0;
    }
    return -1;
}

static __always_inline __u16 str_cp(char *dst, const char *src)
{
    __u16 i;
    #pragma unroll (MAX_FILENAME_LENGTH)
    for (i = 0; src[i] != '\0' && i < MAX_FILENAME_LENGTH; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
    return i;
}

// find the least hot executable binary
static long find_least_ref_bin(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct least_hot_bin *lhb = (struct least_hot_bin *)ctx;

    if (*(__u64 *)value < lhb->count) {
        lhb->count = *(__u64 *)value;
        str_cp(lhb->name, key);
        ctx = lhb;
    }
    return 0;
}

// reset count
static long reset_count(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    *(__u64 *)value = 0;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int watch_hot_bins(struct trace_event_raw_sys_enter *ctx) {
    
    const char *filename = (const char *)ctx->args[0];
    char path[MAX_FILENAME_LENGTH] = {0};
        
    long nbits_written = bpf_probe_read_user_str(path, sizeof(path), filename);

    if (nbits_written > 0) {
        if (str_cmp(path, BIN_PATH_LENGTH, BIN_PATH) == 0) {
            __u64 *value = bpf_map_lookup_elem(&bin_freq_map, &path);
            if (value) {
                // when reference count reaches the MAX_VALUE reset all counters
                if (*value + 1 == MAX_VALUE) {
                    // reset all values
                    long (*reset)(struct bpf_map *, const void *, void *, void *) = &reset_count;
                    // find least referenced bin
                    bpf_for_each_map_elem(&bin_freq_map, reset, 0, 0);
                } else {
                    __sync_fetch_and_add(value, 1);
                }
            } else {
                /* Eviction logic is below. 
                   From the most frequently run binaries the top 'X' - this is set in the userspace program,
                   Will be advised for prefetching the kernel
                */
                __u64 c_init = 1;
                if (unique_bins_count == MAX_ENTRIES) {
                    // replace least referenced entry
                    struct least_hot_bin lhb = {0};
                    lhb.count = MAX_VALUE;
                    long (*least_ref)(struct bpf_map *, const void *, void *, void *) = &find_least_ref_bin;
                    // find least referenced bin
                    bpf_for_each_map_elem(&bin_freq_map, least_ref, &lhb, 0);
                    // delete the least referenced bin
                    int res = bpf_map_delete_elem(&bin_freq_map, lhb.name);
                    // check whether entry was found and deleted successfully
                    if (res == 0) {
                        // add new entry to the map
                        bpf_map_update_elem(&bin_freq_map, path, &c_init, BPF_NOEXIST);
                        __sync_fetch_and_sub(&unique_bins_count, 1);
                    }
                } else {
                    // MAX_ENTRIES isn't reached yet, we can safely add a new entry to the map 
                    // add new entry to the map
                    int res = bpf_map_update_elem(&bin_freq_map, path, &c_init, BPF_NOEXIST);
                    if (res == 0) {
                        __sync_fetch_and_add(&unique_bins_count, 1);
                            //bpf_printk("entry was inserted. %s:%d", path, c_init);
                    }

                }
            }
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";