// SPDX-License-Identifier: GPL-2.0
//
// fishbowl-v2 credential-access probe.
//
// Attaches to `sys_enter_openat` and emits a ringbuf record for every file
// open. Yes, that's noisy — userspace filters down to enrolled processes and
// classified-as-credential paths. Kernel-side filtering (PID map populated by
// userspace) is a v0.5 optimization; on a dev endpoint open() rates are in
// the low thousands per second, well within ringbuf capacity.
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

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct sys_enter_openat_args *ctx) {
    struct credacc_event *e = bpf_ringbuf_reserve(&cred_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->flags = (__s32)ctx->flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
