// SPDX-License-Identifier: GPL-2.0
//
// ATEN minimal exec probe.
//
// Attaches to the sched_process_exec tracepoint and emits one ringbuf record
// per successful exec containing only what the kernel cheaply gives us:
//   - timestamp (CLOCK_BOOTTIME, ns)
//   - pid / uid of the newly-exec'd task
//   - kernel `comm` (capped 16 bytes)
//   - the executable filename (from the tracepoint payload's data_loc)
//
// Everything else for the schema's Process block (ppid, full cmdline, cwd,
// parent_chain, user name, start_time) is read from /proc on the user-space
// side. This keeps the BPF code minimal and avoids vmlinux.h coupling — we do
// not touch task_struct here. The tradeoff is one open/read per exec event,
// which is fine on dev-endpoint exec rates (~10s per minute, not 10s of K).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct exec_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Layout of the sched/sched_process_exec tracepoint args.
// Format is stable across kernels and documented at
// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
struct sched_exec_tp_args {
    __u64 __unused_pad;
    __u32 __data_loc_filename;
    __s32 pid;
    __s32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct sched_exec_tp_args *ctx) {
    struct exec_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        // Ringbuf full. v0.x: drop and move on. v1.x should count drops via a
        // counter map so we can surface "you're losing events" in the daemon log.
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_boot_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // The filename lives at ctx + (data_loc_filename & 0xFFFF). The high 16
    // bits of data_loc are the field's length; we ignore it and rely on the
    // string being null-terminated and capped by MAX_FILENAME_LEN.
    unsigned int filename_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              (void *)ctx + filename_off);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
