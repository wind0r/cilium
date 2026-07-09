// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Datapath test for the L7/Ingress branch of the service ICMP PMTU relay.
 *
 * An ICMPv4 "fragmentation needed" addressed to an L7 (Envoy) service VIP is
 * flooded to every node in cilium_node_map_v2 with the outer destination
 * rewritten to each node's IP; the node the error landed on (fib_lookup
 * NOT_FWDED for its own IP) has the original delivered to its local host stack
 * instead. This test drives handle_icmp_svc_pmtu_v4() with a mocked fib_lookup
 * and a node map holding one remote node (SUCCESS -> clone_redirect, deduped)
 * and one local node (NOT_FWDED -> local delivery), and asserts that:
 *   - the helper returns CTX_ACT_OK (a local node exists);
 *   - the outer destination ends up rewritten to the local node IP;
 *   - the embedded packet is left untouched (the L7 flood never rewrites it).
 *
 * clone_redirect() is a raw helper and cannot run under BPF_PROG_RUN; the
 * remote node still drives that branch but its delivery is not asserted.
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_DSR
#define ENABLE_L7_LB
#define ENABLE_SVC_ICMP_PMTU_RELAY
#include <bpf/config/global.h>

/* Satisfy the nat.h -> egress_gateway.h -> encap.h include chain. */
#define ENCAP_IFINDEX	42
#define ENCAP4_IFINDEX	42
#define ENCAP6_IFINDEX	42

/* The relay does not select a backend on the L7 path, so use the unit-test
 * "first slot" selection to avoid needing the maglev maps. */
#define LB_SELECTION	LB_SELECTION_FIRST

/* Mock the fib lookup used by the flood (the real one cannot run here). */
#define fib_lookup	mock_fib_lookup

#include "nodeport_defaults.h"

#define ROUTER_IP	bpf_htonl(0x0a000002)	/* 10.0.0.2   (ICMP source) */
#define VIP_ADDR	bpf_htonl(0x0a00000a)	/* 10.0.0.10  (L7 VIP)       */
#define CLIENT_IP	bpf_htonl(0x0a0000f0)	/* 10.0.0.240 (client)       */
#define LOCAL_NODE_IP	bpf_htonl(0x0a000033)	/* 10.0.0.51  (this node)    */
#define REMOTE_NODE_IP	bpf_htonl(0x0a000034)	/* 10.0.0.52  (other node)   */
#define SVC_PORT	bpf_htons(443)
#define CLIENT_PORT	bpf_htons(12345)
#define PROXY_PORT	11310
#define REVNAT		1
#define PMTU_LOCAL_NODE_ID	1
#define PMTU_REMOTE_NODE_ID	2

static long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
			    __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = 1;

	/* The local node's own IP is not forwarded. */
	if (params->ipv4_dst == LOCAL_NODE_IP)
		return BPF_FIB_LKUP_RET_NOT_FWDED;

	/* Any other (remote) node resolves successfully. */
	memset(params->smac, 0, ETH_ALEN);
	memset(params->dmac, 0, ETH_ALEN);
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/pmtu.h>
#include "lib/lb.h"

static volatile const __u8 smac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 1};
static volatile const __u8 dmac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 2};

static __always_inline void add_node(__be32 ip, __u16 id)
{
	struct node_key key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = { .be32 = ip },
	};
	struct node_value val = { .id = id, };

	map_update_elem(&cilium_node_map_v2, &key, &val, BPF_ANY);
}

PKTGEN("tc", "svc_icmp_pmtu_relay_l7_v4")
int svc_icmp_pmtu_relay_l7_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *ip4;
	struct icmphdr *icmp;
	struct iphdr inner_ip = {
		.version = 4,
		.ihl = 5,
		.protocol = IPPROTO_TCP,
		.saddr = VIP_ADDR,	/* Envoy reply is sourced from the VIP */
		.daddr = CLIENT_IP,
	};
	struct tcphdr inner_tcp = {
		.source = SVC_PORT,
		.dest = CLIENT_PORT,
		.doff = 5,
	};

	pktgen__init(&builder, ctx);

	ip4 = pktgen__push_ipv4_packet(&builder, (__u8 *)smac, (__u8 *)dmac,
				       ROUTER_IP, VIP_ADDR);
	if (!ip4)
		return TEST_ERROR;
	ip4->protocol = IPPROTO_ICMP;

	icmp = pktgen__push_icmphdr(&builder);
	if (!icmp)
		return TEST_ERROR;
	icmp->type = ICMP_DEST_UNREACH;
	icmp->code = ICMP_FRAG_NEEDED;
	icmp->un.frag.mtu = bpf_htons(1400);

	if (!pktgen__push_data(&builder, &inner_ip, sizeof(inner_ip)))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, &inner_tcp, sizeof(inner_tcp)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "svc_icmp_pmtu_relay_l7_v4")
int svc_icmp_pmtu_relay_l7_v4_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__s8 ext_err = 0;
	int l4_off, ret;

	/* L7 service (Envoy) at VIP:443. */
	lb_v4_add_l7_service(VIP_ADDR, SVC_PORT, IPPROTO_TCP, REVNAT, PROXY_PORT);

	/* One remote node (flood clones to it) and one local node (original is
	 * delivered locally). */
	add_node(REMOTE_NODE_IP, PMTU_REMOTE_NODE_ID);
	add_node(LOCAL_NODE_IP, PMTU_LOCAL_NODE_ID);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return TEST_ERROR;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	ret = handle_icmp_svc_pmtu_v4(ctx, ip4, l4_off, &ext_err);
	/* A local node exists, so the helper delivers the original locally. */
	if (ret != CTX_ACT_OK)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_pmtu_relay_l7_v4")
int svc_icmp_pmtu_relay_l7_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *ip4, *inner_ip;
	struct icmphdr *icmp;
	struct tcphdr *inner_tcp;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);

	ip4 = data + sizeof(*status_code) + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("outer ip out of bounds");
	/* Original delivered locally: outer dst rewritten to the local node IP. */
	if (ip4->daddr != LOCAL_NODE_IP)
		test_fatal("outer dst not rewritten to the local node IP");

	icmp = (void *)ip4 + sizeof(*ip4);
	if ((void *)icmp + sizeof(*icmp) > data_end)
		test_fatal("icmp out of bounds");

	/* The L7 flood must never touch the embedded packet. */
	inner_ip = (void *)icmp + sizeof(*icmp);
	if ((void *)inner_ip + sizeof(*inner_ip) > data_end)
		test_fatal("embedded ip out of bounds");
	if (inner_ip->saddr != VIP_ADDR)
		test_fatal("embedded src must remain the VIP");
	if (inner_ip->daddr != CLIENT_IP)
		test_fatal("embedded dst must remain the client");

	inner_tcp = (void *)inner_ip + sizeof(*inner_ip);
	if ((void *)inner_tcp + sizeof(*inner_tcp) > data_end)
		test_fatal("embedded tcp out of bounds");
	if (inner_tcp->source != SVC_PORT)
		test_fatal("embedded L4 source must remain the service port");

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
