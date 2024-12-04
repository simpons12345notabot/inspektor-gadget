// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on tcpconnect(8) from BCC by Brendan Gregg
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/types.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

/* The maximum number of ports to filter */
#define MAX_PORTS 64

struct ipv4_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
};

struct ipv6_flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 dport;
};

struct src_dst {
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	__u64 latency;
	gadget_errno error_raw;
};

const volatile int filter_ports[MAX_PORTS];
const volatile int filter_ports_len = 0;
const volatile bool do_count = 0;
const volatile bool calculate_latency = false;
const volatile __u64 targ_min_latency_ns = 0;

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10

// sockets_per_process keeps track of the sockets between:
// - kprobe inet_stream_connect
// - kretprobe inet_stream_connect
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct sock *);
} sockets_per_process SEC(".maps");

// src_dst_per_process keeps track of the src and dst information
// between tcp_v4/6_connect and the return of inet_stream_connect
// Since tcp_v4/6_connect is directly inside of inet_stream_connect,
// we do not need to keep a huge number of entries.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct src_dst);
} src_dst_per_process SEC(".maps");

struct piddata {
	struct gadget_process proc;
	u64 ts;
};

// sockets_latency keeps track of sockets to calculate the latency between:
// - enter_tcp_connect (where the socket is added in the map)
// - handle_tcp_rcv_state_process (where the socket is removed from the map)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock *);
	__type(value, struct piddata);
} sockets_latency SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv4_flow_key);
	__type(value, u64);
} ipv4_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv6_flow_key);
	__type(value, u64);
} ipv6_count SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(tcpconnect, events, event);

static __always_inline bool filter_port(__u16 port)
{
	int i;

	if (filter_ports_len == 0)
		return false;

	// This loop was written a bit different than the upstream one
	// to avoid a verifier error.
	for (i = 0; i < MAX_PORTS; i++) {
		if (i >= filter_ports_len)
			break;
		if (port == filter_ports[i])
			return false;
	}
	return true;
}

static __always_inline int enter_inet_stream_connect(struct pt_regs *ctx,
						     struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u32 uid = (u32)uid_gid;
	struct piddata piddata;

	if (gadget_should_discard_current())
		return 0;

	if (calculate_latency) {
		gadget_process_populate(&piddata.proc);
		piddata.ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&sockets_latency, &sk, &piddata, 0);
	} else {
		bpf_map_update_elem(&sockets_per_process, &tid, &sk, 0);
	}
	return 0;
}

static __always_inline void count_v4(struct sock *sk, __u16 dport)
{
	struct ipv4_flow_key key = {};
	static __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&key.saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&key.daddr, sk, __sk_common.skc_daddr);
	key.dport = dport;
	val = bpf_map_lookup_or_try_init(&ipv4_count, &key, &zero);
	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void count_v6(struct sock *sk, __u16 dport)
{
	struct ipv6_flow_key key = {};
	static const __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&key.saddr, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&key.daddr, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	key.dport = dport;

	val = bpf_map_lookup_or_try_init(&ipv6_count, &key, &zero);
	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void
read_l4endpoints_from_sock_v4(struct gadget_l4endpoint_t *src,
			      struct gadget_l4endpoint_t *dst, struct sock *sk)
{
	src->version = dst->version = 4;
	BPF_CORE_READ_INTO(&src->addr_raw.v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&dst->addr_raw.v4, sk, __sk_common.skc_daddr);
	dst->port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	src->port = BPF_CORE_READ(sk, __sk_common.skc_num);
}

static __always_inline void
read_l4endpoints_from_sock_v6(struct gadget_l4endpoint_t *src,
			      struct gadget_l4endpoint_t *dst, struct sock *sk)
{
	src->version = dst->version = 6;
	BPF_CORE_READ_INTO(&src->addr_raw.v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&dst->addr_raw.v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	dst->port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	src->port = BPF_CORE_READ(sk, __sk_common.skc_num);
}

static __always_inline void
read_l4endpoints_from_sock(struct gadget_l4endpoint_t *src,
			   struct gadget_l4endpoint_t *dst, struct sock *sk,
			   int family)
{
	src->proto_raw = dst->proto_raw = IPPROTO_TCP;

	if (family == AF_INET)
		return read_l4endpoints_from_sock_v4(src, dst, sk);
	else if (family == AF_INET6)
		return read_l4endpoints_from_sock_v6(src, dst, sk);
}

static __always_inline int exit_inet_stream_connect(struct pt_regs *ctx,
						    int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;
	struct src_dst *src_dst_entry;
	__u16 dport;
	unsigned short family;
	struct event *event;

	src_dst_entry = bpf_map_lookup_elem(&src_dst_per_process, &tid);

	skpp = bpf_map_lookup_elem(&sockets_per_process, &tid);
	if (!skpp)
		return 0;

	sk = *skpp;

	if (src_dst_entry) {
		dport = src_dst_entry->dst.port;
	} else {
		dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	}
	if (filter_port(dport))
		goto end;

	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	if (do_count) {
		if (family == AF_INET)
			count_v4(sk, dport);
		else
			count_v6(sk, dport);

		return 0;
	}

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto end;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->error_raw = -ret;

	if (src_dst_entry) {
		event->src = src_dst_entry->src;
		event->dst = src_dst_entry->dst;
	} else {
		// src_dst_entry is not set when tcp_v{4|6}_connect is not called, e.g.,
		// when calling inet_stream_connect on an already connected socket. So,
		// try to read the endpoints from the socket here.
		read_l4endpoints_from_sock(&event->src, &event->dst, sk,
					   family);
	}

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

end:
	bpf_map_delete_elem(&sockets_per_process, &tid);
	if (src_dst_entry)
		bpf_map_delete_elem(&src_dst_per_process, &tid);
	return 0;
}

static __always_inline int cleanup_sockets_latency_map(const struct sock *sk)
{
	bpf_map_delete_elem(&sockets_latency, &sk);
	return 0;
}

static __always_inline int handle_tcp_rcv_state_process(void *ctx,
							struct sock *sk)
{
	struct piddata *piddatap;
	struct event *event;
	unsigned int family;
	u64 ts;

	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
		return 0;

	piddatap = bpf_map_lookup_elem(&sockets_latency, &sk);
	if (!piddatap)
		return 0;

	ts = bpf_ktime_get_ns();
	if (ts < piddatap->ts)
		goto cleanup;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto cleanup;

	event->latency = ts - piddatap->ts;
	if (targ_min_latency_ns && event->latency < targ_min_latency_ns)
		goto cleanup;

	__builtin_memcpy(&event->proc, &piddatap->proc, sizeof(event->proc));
	event->src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	// host expects data in host byte order
	event->dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	event->src.proto_raw = event->dst.proto_raw = IPPROTO_TCP;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		event->src.version = event->dst.version = 4;
		event->src.addr_raw.v4 =
			BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event->dst.addr_raw.v4 =
			BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		event->src.version = event->dst.version = 6;
		BPF_CORE_READ_INTO(
			&event->src.addr_raw.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event->dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_submit_buf(ctx, &events, event, sizeof(*event));

cleanup:
	return cleanup_sockets_latency_map(sk);
}

SEC("kprobe/inet_stream_connect")
int BPF_KPROBE(ig_inet_stream_connect, struct socket *sock,
	       struct sockaddr *uaddr, int addr_len, int flags)
{
	return enter_inet_stream_connect(ctx, BPF_CORE_READ(sock, sk));
}

SEC("kretprobe/inet_stream_connect")
int BPF_KRETPROBE(ig_inet_stream_connect_ret, int ret)
{
	return exit_inet_stream_connect(ctx, ret);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KPROBE(ig_tcp_v4_connect, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;
	struct src_dst src_dst_entry;
	unsigned short family;

	skpp = bpf_map_lookup_elem(&sockets_per_process, &tid);
	if (!skpp)
		return 0;
	sk = *skpp;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	read_l4endpoints_from_sock(&src_dst_entry.src, &src_dst_entry.dst, sk,
				   family);

	bpf_map_update_elem(&src_dst_per_process, &tid, &src_dst_entry, 0);
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KPROBE(ig_tcp_v6_connect, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;
	struct src_dst src_dst_entry;
	unsigned short family;

	skpp = bpf_map_lookup_elem(&sockets_per_process, &tid);
	if (!skpp)
		return 0;
	sk = *skpp;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	read_l4endpoints_from_sock(&src_dst_entry.src, &src_dst_entry.dst, sk,
				   family);

	bpf_map_update_elem(&src_dst_per_process, &tid, &src_dst_entry, 0);
	return 0;
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(ig_tcp_rsp, struct sock *sk)
{
	return handle_tcp_rcv_state_process(ctx, sk);
}

// tcp_destroy_sock is fired for ipv4 and ipv6.
SEC("tracepoint/tcp/tcp_destroy_sock")
int ig_tcp_destroy(struct trace_event_raw_tcp_event_sk *ctx)
{
	return cleanup_sockets_latency_map(ctx->skaddr);
}

char LICENSE[] SEC("license") = "GPL";
