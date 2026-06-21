// SPDX-License-Identifier: GPL-2.0
//
// ATEN network-egress probe.
//
// Attaches to `sys_enter_connect` and emits a ringbuf record per connect()
// syscall. We copy enough sockaddr bytes to cover IPv4, IPv6, and AF_UNIX
// socket paths; userspace parses the family and drops uninteresting sockets.
//
// As with the openat probe, a BPF-side PID map drops non-agent traffic before
// ring-buffer allocation.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_SOCKADDR 110

struct connect_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 addrlen;
    char comm[TASK_COMM_LEN];
    __u8 sockaddr[MAX_SOCKADDR];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} connect_events SEC(".maps");

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

// Layout for tracepoint/syscalls/sys_enter_connect. Same x86_64 8-byte arg
// padding as openat. Cross-checked against /sys/kernel/tracing/events/
// syscalls/sys_enter_connect/format on 6.17.
struct sys_enter_connect_args {
    __u64 __unused_pad;       // 0..8   common header
    __s64 __syscall_nr;       // 8..16
    __s64 fd;                 // 16..24
    const void *uservaddr;    // 24..32 — struct sockaddr *
    __s64 addrlen;            // 32..40
};

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct sys_enter_connect_args *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&enrolled_pids, &pid)) {
        return 0;
    }
    // Drop families we know are uninteresting before reserving a ringbuf
    // record. Keep AF_UNIX: userspace classifies high-signal local IPC
    // surfaces like docker.sock / SSH agent / gpg-agent and drops the rest.
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr);
    if (family != 1 /* AF_UNIX */ && family != 2 /* AF_INET */ && family != 10 /* AF_INET6 */) {
        return 0;
    }
    struct connect_event *e = bpf_ringbuf_reserve(&connect_events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return 0;
    }
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 alen = (__u32)ctx->addrlen;
    if (alen > MAX_SOCKADDR) {
        alen = MAX_SOCKADDR;
    }
    e->addrlen = alen;
    __builtin_memset(e->sockaddr, 0, sizeof(e->sockaddr));
    bpf_probe_read_user(e->sockaddr, alen, ctx->uservaddr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
