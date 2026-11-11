// SPDX-License-Identifier: GPL-2.0-only OR MIT
// The kernel only exposes the helpers used here to GPL-compatible programs,
// so this file is dual licensed; the rest of the project is Apache-2.0.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

#define AF_INET 2
#define AF_INET6 10
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define DNS_PORT 53
#define DATA_MAX 512
#define TASK_COMM_LEN 16

enum event_kind {
	EVENT_EXEC = 1,
	EVENT_FORK = 2,
	EVENT_EXIT = 3,
	EVENT_OPEN = 4,
	EVENT_CONNECT = 5,
	EVENT_DNS = 6,
};

struct event {
	__u32 kind;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u16 family;
	__u16 dport;
	__u8 proto;
	__u8 pad[3];
	__u8 daddr[16];
	__u32 data_len;
	__u8 comm[TASK_COMM_LEN];
	__u8 data[DATA_MAX];
};

/* Keeps the type in BTF so bpf2go can generate its Go counterpart. */
const struct event *unused_event __attribute__((unused));

struct udp_key {
	__u32 pid;
	__u16 dport;
	__u16 family;
	__u8 daddr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

/* Processes whose file opens are reported: session roots and their descendants. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} tracked SEC(".maps");

/* UDP has no connect step, so report each process/destination pair once. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct udp_key);
	__type(value, __u8);
} udp_seen SEC(".maps");

char LICENSE[] SEC("license") = "Dual MIT/GPL";

static __always_inline struct event *reserve(__u32 kind)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt) {
		__u32 zero = 0;
		__u64 *count = bpf_map_lookup_elem(&drops, &zero);
		if (count)
			__sync_fetch_and_add(count, 1);
		return NULL;
	}
	__builtin_memset(evt, 0, sizeof(*evt) - DATA_MAX);
	evt->kind = kind;
	return evt;
}

static __always_inline void fill_current(struct event *evt)
{
	struct task_struct *task = bpf_get_current_task_btf();
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	evt->ppid = BPF_CORE_READ(task, real_parent, tgid);
	evt->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *task, int old_pid, struct linux_binprm *bprm)
{
	struct event *evt = reserve(EVENT_EXEC);
	if (!evt)
		return 0;
	fill_current(evt);
	long len = bpf_probe_read_kernel_str(evt->data, DATA_MAX, BPF_CORE_READ(bprm, filename));
	evt->data_len = len > 0 ? len - 1 : 0;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	/* new threads share the parent's tgid and are not processes */
	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))
		return 0;
	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);
	if (bpf_map_lookup_elem(&tracked, &parent_tgid)) {
		__u8 one = 1;
		bpf_map_update_elem(&tracked, &child_tgid, &one, BPF_ANY);
	}
	struct event *evt = reserve(EVENT_FORK);
	if (!evt)
		return 0;
	evt->pid = child_tgid;
	evt->ppid = parent_tgid;
	evt->uid = (__u32)bpf_get_current_uid_gid();
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *task)
{
	if (BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid))
		return 0;
	__u32 tgid = BPF_CORE_READ(task, tgid);
	bpf_map_delete_elem(&tracked, &tgid);
	struct event *evt = reserve(EVENT_EXIT);
	if (!evt)
		return 0;
	evt->pid = tgid;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

static __always_inline bool dotted(struct dentry *dentry)
{
	char first = 0;
	bpf_probe_read_kernel(&first, 1, BPF_CORE_READ(dentry, d_name.name));
	return first == '.';
}

/*
 * Credentials live in dotfiles or dot directories (~/.ssh/id_rsa,
 * ~/.config/gh/hosts.yml, .env), so only opens with a dot in the last three
 * path components leave the kernel; user space applies the exact rules.
 */
SEC("fentry/security_file_open")
int BPF_PROG(on_open, struct file *file)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
	struct dentry *grandparent = BPF_CORE_READ(parent, d_parent);
	if (!dotted(dentry) && !dotted(parent) && !dotted(grandparent))
		return 0;
	struct event *evt = reserve(EVENT_OPEN);
	if (!evt)
		return 0;
	fill_current(evt);
	long len = bpf_d_path(&file->f_path, (char *)evt->data, DATA_MAX);
	evt->data_len = len > 0 ? len - 1 : 0;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

static __always_inline void emit_connect(__u8 proto, __u16 family, __be16 dport, const void *daddr)
{
	struct event *evt = reserve(EVENT_CONNECT);
	if (!evt)
		return;
	fill_current(evt);
	evt->proto = proto;
	evt->family = family;
	evt->dport = bpf_ntohs(dport);
	if (family == AF_INET)
		bpf_probe_read_kernel(evt->daddr, 4, daddr);
	else
		bpf_probe_read_kernel(evt->daddr, 16, daddr);
	bpf_ringbuf_submit(evt, 0);
}

SEC("fentry/tcp_connect")
int BPF_PROG(on_tcp_connect, struct sock *sk)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	if (family == AF_INET) {
		__be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		emit_connect(IPPROTO_TCP, family, dport, &daddr);
	} else if (family == AF_INET6) {
		struct in6_addr daddr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
		emit_connect(IPPROTO_TCP, family, dport, &daddr);
	}
	return 0;
}

static __always_inline void udp_once(__u16 family, __be16 dport, const void *daddr)
{
	struct udp_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.family = family;
	key.dport = dport;
	bpf_probe_read_kernel(key.daddr, family == AF_INET ? 4 : 16, daddr);
	__u8 one = 1;
	if (bpf_map_update_elem(&udp_seen, &key, &one, BPF_NOEXIST) != 0)
		return;
	emit_connect(IPPROTO_UDP, family, dport, key.daddr);
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	struct sockaddr_in *addr = BPF_CORE_READ(msg, msg_name);
	struct sockaddr_in dest = {};
	if (addr) {
		bpf_probe_read_kernel(&dest, sizeof(dest), addr);
	} else {
		dest.sin_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
		dest.sin_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	}
	if (dest.sin_port)
		udp_once(AF_INET, dest.sin_port, &dest.sin_addr);
	return 0;
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(on_udpv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
	struct sockaddr_in6 *addr = BPF_CORE_READ(msg, msg_name);
	struct sockaddr_in6 dest = {};
	if (addr) {
		bpf_probe_read_kernel(&dest, sizeof(dest), addr);
	} else {
		dest.sin6_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
		dest.sin6_addr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
	}
	if (dest.sin6_port)
		udp_once(AF_INET6, dest.sin6_port, &dest.sin6_addr);
	return 0;
}

/* DNS answers name each destination IP; the payload is parsed in user space. */
SEC("cgroup_skb/ingress")
int on_ingress(struct __sk_buff *skb)
{
	__u32 udp_offset;
	__u8 proto;
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		__u8 version_ihl;
		if (bpf_skb_load_bytes(skb, 0, &version_ihl, 1) || bpf_skb_load_bytes(skb, 9, &proto, 1))
			return 1;
		udp_offset = (version_ihl & 0x0f) * 4;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		if (bpf_skb_load_bytes(skb, 6, &proto, 1))
			return 1;
		udp_offset = 40;
	} else {
		return 1;
	}
	if (proto != IPPROTO_UDP)
		return 1;
	__be16 sport;
	if (bpf_skb_load_bytes(skb, udp_offset, &sport, sizeof(sport)) || sport != bpf_htons(DNS_PORT))
		return 1;

	__u32 payload = udp_offset + 8;
	if (skb->len <= payload)
		return 1;
	__u32 len = skb->len - payload;
	if (len > DATA_MAX)
		len = DATA_MAX;
	/* clang drops a len == 0 test it can prove false; the mask keeps the
	 * verifier's view of len within [1, DATA_MAX] */
	len = ((len - 1) & (DATA_MAX - 1)) + 1;

	struct event *evt = reserve(EVENT_DNS);
	if (!evt)
		return 1;
	if (bpf_skb_load_bytes(skb, payload, evt->data, len)) {
		bpf_ringbuf_discard(evt, 0);
		return 1;
	}
	evt->data_len = len;
	bpf_ringbuf_submit(evt, 0);
	return 1;
}
