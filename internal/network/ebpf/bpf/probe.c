// SPDX-License-Identifier: GPL-2.0
// Minimal connect()-event tap: emits one ring buffer record per
// outbound TCP connection attempt observed on the local host, tagged
// with the calling process's pid/comm and the destination addr/port.
// All Tor-port/Tor-IP filtering happens in Go userspace (see service.go)
// — this program does no filtering of its own, by design.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct connect_event {
	__u32 pid;
	char comm[16];
	__u32 daddr; // network byte order, IPv4 only for v1
	__u16 dport; // network byte order
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

static __always_inline int emit_connect_event(struct sock *sk)
{
	struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk)
{
	return emit_connect_event(sk);
}

char _license[] SEC("license") = "GPL";
