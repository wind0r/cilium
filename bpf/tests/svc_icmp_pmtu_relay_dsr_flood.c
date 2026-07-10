// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Datapath test for the non-Maglev DSR branch of the service ICMP PMTU relay.
 *
 * A DSR backend can only be re-derived statelessly under Maglev. Under any
 * other algorithm the relay instead floods the error to every backend of the
 * service (the one owning the flow caches the PMTU, the rest ignore it). This
 * test uses the default (random) algorithm and two backends, sends an ICMPv4
 * "fragmentation needed" addressed to the VIP, and checks that:
 *   - handle_icmp_svc_pmtu_v4() consumes the original (returns DROP_PMTU_RELAYED),
 *   - the packet was re-addressed backend by backend, ending at the last backend
 *     (VIP -> backend1 -> backend2), which proves the per-backend rewrite chain.
 *
 * clone_redirect() does not deliver under BPF_PROG_RUN, so the per-backend copies
 * themselves are not asserted (as with the L7 flood test); the return code and
 * the final rewrite are.
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_DSR
#define ENABLE_SVC_ICMP_PMTU_RELAY
#include <bpf/config/global.h>

#define TEST_REVNAT		       1

/* Satisfy the nat.h -> egress_gateway.h -> encap.h include chain. */
#define ENCAP_IFINDEX	42
#define ENCAP4_IFINDEX	42
#define ENCAP6_IFINDEX	42

#include "nodeport_defaults.h"

/* No LB_DEFAULT_ALG override: it defaults to LB_SELECTION_RANDOM, i.e. a
 * non-Maglev DSR service, which is exactly the flood path under test. */

/* The backend flood is gated on HAVE_LOOP (bpf_loop, kernel >= 5.17), which the
 * agent probes at startup. Force it on so the flood is compiled into the test. */
#define HAVE_LOOP 1

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/pmtu.h>
#include "lib/lb.h"

#define ROUTER_IP	bpf_htonl(0x0a000002)	/* 10.0.0.2   (ICMP source) */
#define VIP_ADDR	bpf_htonl(0x0a00000a)	/* 10.0.0.10  (service VIP)  */
#define CLIENT_IP	bpf_htonl(0x0a0000f0)	/* 10.0.0.240 (client)       */
#define BACKEND1_IP	bpf_htonl(0x0a000105)	/* 10.0.1.5   (backend 1)    */
#define BACKEND2_IP	bpf_htonl(0x0a000106)	/* 10.0.1.6   (backend 2)    */
#define SVC_PORT	bpf_htons(80)
#define CLIENT_PORT	bpf_htons(12345)
#define BACKEND_PORT	bpf_htons(8080)
#define BACKEND1_ID	124
#define BACKEND2_ID	125

static volatile const __u8 smac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 1};
static volatile const __u8 dmac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 2};

PKTGEN("tc", "svc_icmp_pmtu_relay_dsr_flood_v4")
int svc_icmp_pmtu_relay_dsr_flood_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *ip4;
	struct icmphdr *icmp;
	struct iphdr inner_ip = {
		.version = 4,
		.ihl = 5,
		.protocol = IPPROTO_TCP,
		.saddr = VIP_ADDR,	/* backend reply is sourced from the VIP */
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

	/* Embedded (offending) packet: VIP:svc_port -> client. */
	if (!pktgen__push_data(&builder, &inner_ip, sizeof(inner_ip)))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, &inner_tcp, sizeof(inner_tcp)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "svc_icmp_pmtu_relay_dsr_flood_v4")
int svc_icmp_pmtu_relay_dsr_flood_v4_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__s8 ext_err = 0;
	int l4_off, ret;

	/* DSR service VIP:80 with TWO backends (default = random algorithm). */
	lb_v4_add_service_with_flags(VIP_ADDR, SVC_PORT, IPPROTO_TCP, 2, TEST_REVNAT,
				     SVC_FLAG_ROUTABLE, SVC_FLAG_FWD_MODE_DSR);
	lb_v4_add_backend(VIP_ADDR, SVC_PORT, 1, BACKEND1_ID,
			  BACKEND1_IP, BACKEND_PORT, IPPROTO_TCP, 0);
	lb_v4_add_backend(VIP_ADDR, SVC_PORT, 2, BACKEND2_ID,
			  BACKEND2_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return TEST_ERROR;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	ret = handle_icmp_svc_pmtu_v4(ctx, ip4, l4_off, &ext_err);
	/* The flood consumes the original after cloning to each backend. */
	if (ret != DROP_PMTU_RELAYED)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_pmtu_relay_dsr_flood_v4")
int svc_icmp_pmtu_relay_dsr_flood_v4_check(const struct __ctx_buff *ctx)
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

	/* The packet was re-addressed once per backend; the last iteration leaves
	 * it addressed to the last backend (VIP -> backend1 -> backend2). */
	ip4 = data + sizeof(*status_code) + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("outer ip out of bounds");
	if (ip4->daddr != BACKEND2_IP)
		test_fatal("outer dst not rewritten to the last backend");

	icmp = (void *)ip4 + sizeof(*ip4);
	if ((void *)icmp + sizeof(*icmp) > data_end)
		test_fatal("icmp out of bounds");

	inner_ip = (void *)icmp + sizeof(*icmp);
	if ((void *)inner_ip + sizeof(*inner_ip) > data_end)
		test_fatal("embedded ip out of bounds");
	if (inner_ip->saddr != BACKEND2_IP)
		test_fatal("embedded src not rewritten to the last backend");
	if (inner_ip->daddr != CLIENT_IP)
		test_fatal("embedded dst must remain the client");

	inner_tcp = (void *)inner_ip + sizeof(*inner_ip);
	if ((void *)inner_tcp + sizeof(*inner_tcp) > data_end)
		test_fatal("embedded tcp out of bounds");
	if (inner_tcp->source != BACKEND_PORT)
		test_fatal("embedded L4 source not rewritten to the backend port");
	if (inner_tcp->dest != CLIENT_PORT)
		test_fatal("embedded L4 dest must remain the client port");

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
