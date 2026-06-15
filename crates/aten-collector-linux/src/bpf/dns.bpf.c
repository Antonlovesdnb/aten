// SPDX-License-Identifier: GPL-2.0
//
// ATEN DNS-query probe.
//
// A uprobe on glibc's `getaddrinfo()` — the resolver-library entry point that
// curl, node, python, and essentially every dynamically-linked agent tool
// funnel name resolution through. We capture the `node` argument (the hostname
// being resolved). This is the resolver-LIBRARY view, deliberately chosen over
// parsing UDP :53 off the wire: it's one stable symbol, gives the clean ASCII
// name, and matches the project's tracepoint-style "noisy probe, filter in
// userspace" pattern.
//
// Documented gaps (v0.x): statically-linked binaries and tools that issue raw
// DNS (e.g. `dig`, custom resolvers) bypass getaddrinfo and are invisible
// here; the query *type* isn't known at this layer (getaddrinfo resolves A and
// AAAA together) so userspace tags these `Other`; and the resolved answers
// would require a uretprobe walking `struct addrinfo` — left for later, the
// schema's `answers` field is best-effort and stays empty on Linux for now.
//
// We avoid vmlinux.h (same as the other probes). A uprobe's context IS a
// `struct pt_regs`, so we hand-define the layout per arch and read the first
// argument register. The arch is selected by -D__TARGET_ARCH_* passed from
// build.rs (from CARGO_CFG_TARGET_ARCH); x86_64 and arm64 are supported. Any
// other arch compiles to a no-op (node always NULL → no emission) rather than
// reading a wrong register and emitting a garbage hostname.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_QNAME_LEN 256

#if defined(__TARGET_ARCH_x86_64)
// x86_64 kernel `struct pt_regs` (UAPI-stable). First arg is in rdi.
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi; // arg0: const char *node
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};
#define ATEN_UPROBE_ARG0(ctx) ((ctx)->rdi)
#elif defined(__TARGET_ARCH_arm64)
// arm64 user_pt_regs: first arg is regs[0].
struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};
#define ATEN_UPROBE_ARG0(ctx) ((ctx)->regs[0])
#else
// Unsupported arch — no-op the probe rather than read a wrong register.
struct pt_regs {
    unsigned long __unused;
};
#define ATEN_UPROBE_ARG0(ctx) (0UL)
#endif

struct dns_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char qname[MAX_QNAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} dns_events SEC(".maps");

// bpf_copy_from_user_str is a kfunc (kernel >= 6.11), not a classic helper, so
// it's absent from libbpf's bundled bpf_helper_defs.h. Declare it as a __ksym
// extern (signature cross-checked against this kernel's BTF); libbpf resolves
// it against kernel BTF at load.
extern int bpf_copy_from_user_str(void *dst, __u32 dst__sz,
                                  const void *unsafe_ptr__ign,
                                  __u64 flags) __ksym;

// Manual attach from userspace (libbpf-rs attach_uprobe_with_opts) to
// libc.so.6:getaddrinfo — the SEC name is just a program tag, not an
// auto-attach target.
//
// SLEEPABLE ("uprobe.s"): at the function-entry probe the hostname's .rodata
// page is frequently NOT resident yet — the caller has only loaded the pointer
// into a register, never dereferenced the string — so the non-faulting
// bpf_probe_read_user_str returns empty. A sleepable program can use
// bpf_copy_from_user_str, which is allowed to fault the page in. Verified live:
// the non-sleepable read returned "" for a pristine string literal while real
// callers (curl/ping, which format the name first) read fine; the sleepable
// copy fixes both. Requires kernel >= 6.11 for bpf_copy_from_user_str.
SEC("uprobe.s")
int handle_getaddrinfo(struct pt_regs *ctx) {
    const char *node = (const char *)ATEN_UPROBE_ARG0(ctx);
    if (!node) {
        return 0; // getaddrinfo(NULL, service, ...) — a service-only lookup
    }

    struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    long n = bpf_copy_from_user_str(e->qname, sizeof(e->qname), node, 0);
    if (n < 0) {
        bpf_ringbuf_discard(e, 0); // unreadable pointer — drop, don't emit ""
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
