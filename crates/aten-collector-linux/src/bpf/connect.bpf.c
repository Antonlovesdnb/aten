// SPDX-License-Identifier: GPL-2.0
//
// ATEN network-egress probe.
//
// Attaches to `sys_enter_connect` and emits a ringbuf record per connect()
// syscall. We copy the first 28 bytes of the sockaddr — enough to cover both
// `struct sockaddr_in` (16) and `struct sockaddr_in6` (28) — and let
// userspace parse the family and extract address+port.
//
// As with the openat probe, this fires for every connect() system-wide.
// Userspace filters down to enrolled processes; production should add a
// BPF-side pid_map for kernel-level filtering.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_SOCKADDR 28

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
    struct connect_event *e = bpf_ringbuf_reserve(&connect_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 alen = (__u32)ctx->addrlen;
    if (alen > MAX_SOCKADDR) {
        alen = MAX_SOCKADDR;
    }
    e->addrlen = alen;
    bpf_probe_read_user(e->sockaddr, MAX_SOCKADDR, ctx->uservaddr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
