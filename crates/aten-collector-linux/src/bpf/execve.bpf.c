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
    __u32 kind;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#define EVENT_EXEC 1
#define EVENT_EXIT 2

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

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
        count_drop();
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_boot_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->kind = EVENT_EXEC;
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

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx) {
    struct exec_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_boot_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->kind = EVENT_EXIT;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
