// SPDX-License-Identifier: GPL-2.0
//
// ATEN credential-access probe.
//
// Attaches to `sys_enter_openat` and emits only for PIDs in the enrollment map.
// Userspace seeds roots/descendants at startup; fork/exit tracepoints propagate
// and retire membership in-kernel.
//
// The map is intentionally named `cred_events` rather than `events` so it
// doesn't collide with the execve probe's ringbuf when both skeletons live
// in the same binary.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct credacc_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __s32 flags;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} cred_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_events SEC(".maps");

static __always_inline void count_drop(void) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&dropped_events, &key);
    if (count)
        (*count)++;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u8);
} enrolled_pids SEC(".maps");

struct sched_fork_args {
    __u64 __unused_pad;
    char parent_comm[TASK_COMM_LEN];
    __s32 parent_pid;
    char child_comm[TASK_COMM_LEN];
    __s32 child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int track_fork(struct sched_fork_args *ctx) {
    __u8 *enrolled = bpf_map_lookup_elem(&enrolled_pids, &ctx->parent_pid);
    if (enrolled)
        bpf_map_update_elem(&enrolled_pids, &ctx->child_pid, enrolled, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int forget_exit(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&enrolled_pids, &pid);
    return 0;
}

// Layout for tracepoint/syscalls/sys_enter_openat.
// On x86_64 the kernel pads every syscall arg to 8 bytes regardless of the
// declared C type — `dfd` is `int` but takes size:8 in the format. Mirror
// that exactly or the field offsets shift and `filename` ends up pointing
// at random bytes from the next field. Cross-checked against
// /sys/kernel/tracing/events/syscalls/sys_enter_openat/format on 6.17.
struct sys_enter_openat_args {
    __u64 __unused_pad;   // 0..8   common header
    __s64 __syscall_nr;   // 8..16
    __s64 dfd;            // 16..24
    const char *filename; // 24..32
    __s64 flags;          // 32..40
    __u64 mode;           // 40..48
};

struct open_how_local {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

struct sys_enter_openat2_args {
    __u64 __unused_pad;          // 0..8   common header
    __s64 __syscall_nr;          // 8..16
    __s64 dfd;                   // 16..24
    const char *filename;        // 24..32
    const struct open_how_local *how; // 32..40
    __u64 size;                  // 40..48
};

static __always_inline int emit_open_event(const char *filename, __s64 flags) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&enrolled_pids, &pid)) {
        return 0;
    }
    struct credacc_event *e = bpf_ringbuf_reserve(&cred_events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return 0;
    }
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->flags = (__s32)flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct sys_enter_openat_args *ctx) {
    return emit_open_event(ctx->filename, ctx->flags);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_openat2(struct sys_enter_openat2_args *ctx) {
    struct open_how_local how = {};
    bpf_probe_read_user(&how, sizeof(how), ctx->how);
    return emit_open_event(ctx->filename, (__s64)how.flags);
}

char LICENSE[] SEC("license") = "GPL";
