/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Minimal kernel type definitions for CO-RE. Only the fields the probes read
 * are declared; libbpf relocates them against the running kernel's BTF, so one
 * object works across kernel versions and both supported architectures.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef short __s16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;
#define true 1
#define false 0

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
};

/* uapi context; its layout is fixed ABI, so no relocation */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
};

struct in6_addr {
	__u8 s6_addr[16];
};

struct sockaddr_in {
	__u16 sin_family;
	__be16 sin_port;
	__be32 sin_addr;
	__u8 sin_zero[8];
};

struct sockaddr_in6 {
	__u16 sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct task_struct {
	int pid;
	int tgid;
	struct task_struct *real_parent;
};

struct linux_binprm {
	const char *filename;
};

struct sock_common {
	__be32 skc_daddr;
	__be16 skc_dport;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
};

struct sock {
	struct sock_common __sk_common;
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
};

struct qstr {
	const unsigned char *name;
};

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
};

struct path {
	void *mnt;
	struct dentry *dentry;
};

struct file {
	struct path f_path;
};

#pragma clang attribute pop

#endif
