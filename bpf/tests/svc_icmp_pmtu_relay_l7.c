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
#include "svc_icmp_pmtu_relay_common.h"

#define ENABLE_IPV4
#define ENABLE_L7_LB
#include <bpf/config/global.h>

/* Satisfy the nat.h -> egress_gateway.h -> encap.h include chain. */

/* The relay does not select a backend on the L7 path, so use the unit-test
 * "first slot" selection to avoid needing the maglev maps. */
#define LB_DEFAULT_ALG	LB_SELECTION_FIRST

/* Mock the fib lookup used by the flood (the real one cannot run here). */
#define fib_lookup	mock_fib_lookup

#include "nodeport_defaults.h"

#define ROUTER_IP	bpf_htonl(0x0a000002)	/* 10.0.0.2   (ICMP source) */
#define VIP_ADDR	bpf_htonl(0x0a00000a)	/* 10.0.0.10  (L7 VIP)       */
#define CLIENT_IP	bpf_htonl(0x0a0000f0)	/* 10.0.0.240 (client)       */
#define LOCAL_NODE_IP	bpf_htonl(0x0a000033)	/* 10.0.0.51  (this node)    */
#define REMOTE_NODE_IP	bpf_htonl(0x0a000034)	/* 10.0.0.52  (other node)   */
#define DEAD_NODE_IP	bpf_htonl(0x0a000035)	/* 10.0.0.53  (unreachable)  */
#define SVC_PORT	bpf_htons(443)
#define CLIENT_PORT	bpf_htons(12345)
#define PROXY_PORT	11310
#define REVNAT		1
#define PMTU_LOCAL_NODE_ID	1
#define PMTU_REMOTE_NODE_ID	2
#define PMTU_DEAD_NODE_ID	3

static long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
			    __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = 1;

	/* Neither this node's own IP nor a blackholed route is forwarded; only
	 * the former is a host endpoint. */
	if (params->ipv4_dst == LOCAL_NODE_IP || params->ipv4_dst == DEAD_NODE_IP)
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
#include "lib/node.h"
#include "lib/endpoint.h"

PKTGEN("tc", "svc_icmp_pmtu_relay_l7_v4")
int svc_icmp_pmtu_relay_l7_v4_pktgen(struct __ctx_buff *ctx)
{
	return pmtu_test_pktgen_icmp4(ctx, ROUTER_IP, VIP_ADDR, CLIENT_IP,
				      SVC_PORT, CLIENT_PORT);
}

SETUP("tc", "svc_icmp_pmtu_relay_l7_v4")
int svc_icmp_pmtu_relay_l7_v4_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	int ret;

	/* L7 service (Envoy) at VIP:443. */
	lb_v4_add_l7_service(VIP_ADDR, SVC_PORT, IPPROTO_TCP, REVNAT, PROXY_PORT);

	/* One remote node (flood clones to it), one local node (original is
	 * delivered locally) and one unreachable node, which must be neither. */
	node_v4_add_entry(REMOTE_NODE_IP, PMTU_REMOTE_NODE_ID, 0);
	node_v4_add_entry(LOCAL_NODE_IP, PMTU_LOCAL_NODE_ID, 0);
	node_v4_add_entry(DEAD_NODE_IP, PMTU_DEAD_NODE_ID, 0);
	endpoint_v4_add_entry(LOCAL_NODE_IP, 0, 0, ENDPOINT_F_HOST, 0, 0,
			      (__u8 *)pmtu_test_smac, (__u8 *)pmtu_test_smac);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return TEST_ERROR;

	ret = handle_icmp_svc_pmtu_v4(ctx, ip4, ETH_HLEN + ipv4_hdrlen(ip4));
	/* A local node exists, so the helper delivers the original locally. */
	if (ret != CTX_ACT_OK)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_pmtu_relay_l7_v4")
int svc_icmp_pmtu_relay_l7_v4_check(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;
	struct pmtu_test_pkt4 p;

	test_init();

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);
	if (!pmtu_test_walk4(ctx, &p))
		test_fatal("packet truncated");

	/* Original delivered locally: outer dst rewritten to the local node IP,
	 * with its IP checksum kept valid. */
	if (p.ip4->daddr != LOCAL_NODE_IP)
		test_fatal("outer dst not rewritten to the local node IP");
	if (pmtu_test_csum_ip4(p.ip4) != 0)
		test_fatal("outer ip checksum invalid");

	/* The L7 flood must never touch the embedded packet, and the outer ICMP
	 * checksum (which excludes the IP header) must be untouched. */
	if (p.inner_ip->saddr != VIP_ADDR)
		test_fatal("embedded src must remain the VIP");
	if (p.inner_ip->daddr != CLIENT_IP)
		test_fatal("embedded dst must remain the client");
	if (p.inner_tcp->source != SVC_PORT)
		test_fatal("embedded L4 source must remain the service port");
	if (pmtu_test_csum_icmp4(p.icmp, p.inner_ip, p.inner_tcp) != 0)
		test_fatal("outer icmp checksum invalid");

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
