/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Service PMTU relay for load-balanced service VIPs.
 *
 * When a load-balanced service replies to a client, packets are sourced from
 * the *service VIP*. If such a reply is dropped by a lower-MTU link on the
 * return path (e.g. a tunnel), the resulting ICMP "fragmentation needed" error
 * is addressed to the VIP. It arrives at some node (not necessarily the one
 * holding the flow, because of BGP/ECMP), where the LB datapath cannot classify
 * it (ICMP is not a service protocol) and passes it to the local stack, where
 * it is useless: the VIP is not a local socket and the endpoint that actually
 * needs to lower its PMTU never sees the error, so the connection black-holes.
 *
 * This helper intercepts those errors on the forward path (nodeport_lb{4,6})
 * and, depending on the service forwarding mode:
 *
 *   - DSR backend: re-derive the owning backend statelessly via the same Maglev
 *     hash used on the forward path (the hash excludes the VIP, so any node
 *     derives the same backend), rewrite the error to that backend and forward
 *     it there. The backend's kernel caches the reduced PMTU for the connection.
 *
 *   - L7/Ingress (Envoy): the connection terminates at a proxy on one node that
 *     cannot be re-derived statelessly, so flood the error to every node with
 *     the outer destination rewritten to each node's IP. Only the node holding
 *     the transparent socket matches the embedded packet and caches the PMTU.
 *
 * No per-connection PMTU state is stored in the datapath.
 */

#pragma once

#include "common.h"
#include "lb.h"
#include "nat.h"
#include "conntrack.h"
#include "node.h"
#include "fib.h"
#include "eth.h"
#include "eps.h"
#include "l4.h"
#ifdef ENABLE_IPV6
#include "ipv6.h"
#include "icmp6.h"
#endif

/* The relay hooks into nodeport_lb{4,6}() on the from-netdev path of bpf_host
 * (TC) and bpf_xdp, the programs owning the CILIUM_CALL_IPV{4,6}_FROM_NETDEV
 * slot a relayed error recircles through. Every other object gets no-op stubs
 * so the call sites need no conditional compilation. */
#if defined(ENABLE_SVC_ICMP_PMTU_RELAY) && (defined(IS_BPF_HOST) || defined(IS_BPF_XDP))

/* Bound the relay per service (rev_nat_index) so a spoofed frag-needed spray at
 * a VIP cannot amplify -- especially the L7 flood, which clones to every node.
 * 100 relayed errors/s per service, burstable to 1000, is far above the handful
 * a real connection produces at PMTU-discovery time. Returns true to drop. */
static __always_inline bool
pmtu_relay_ratelimited(__u16 rev_nat_index)
{
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_SVC_ICMP_PMTU_RELAY,
	};
	const struct ratelimit_settings settings = {
		.bucket_size = 1000,
		.tokens_per_topup = 100,
		.topup_interval_ns = NSEC_PER_SEC,
	};

	rkey.key.svc_pmtu_relay.rev_nat_index = rev_nat_index;
	return !ratelimit_check_and_take(&rkey, &settings);
}

/* The L7 flood uses clone_redirect()/fib_lookup(), TC-only helpers, so it is
 * compiled out for XDP (which hands such errors to TC instead).
 *
 * cilium_node_map_v2 is keyed per node *IP*, so a node contributes several
 * entries (InternalIP, CiliumInternalIP, ...). Track the node IDs already
 * flooded so each node is sent one copy. The set is bounded; on clusters with
 * more than PMTU_FLOOD_MAX_NODES nodes the tail may receive duplicate (but
 * harmless -- PMTU caching is idempotent) copies.
 */
#ifndef IS_BPF_XDP
#define PMTU_FLOOD_MAX_NODES 64

/* Per-CPU scratch for the flood dedup set. Map memory is always initialised
 * for the verifier, so the flood only has to reset n_seen. */
struct pmtu_flood_scratch {
	__u16 seen[PMTU_FLOOD_MAX_NODES];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct pmtu_flood_scratch);
	__uint(max_entries, 1);
} cilium_pmtu_flood_scratch __section_maps_btf;

/* Returns true if a copy already reached this node id. */
static __always_inline bool
pmtu_flood_seen(const __u16 *seen, __u32 n_seen, __u16 id)
{
	__u32 i;

	if (!id)
		return false;
	for (i = 0; i < PMTU_FLOOD_MAX_NODES; i++) {
		if (i >= n_seen)
			break;
		if (seen[i] == id)
			return true;
	}
	return false;
}

/* Record a node id once a copy has actually reached it. A node contributes
 * several map entries and not all of them are routable from the netdev (e.g.
 * CiliumInternalIP in tunnel mode), so an entry that fails L2 resolution must
 * not stop a later entry from serving the same node. */
static __always_inline void
pmtu_flood_mark(__u16 *seen, __u32 *n_seen, __u16 id)
{
	if (id && *n_seen < PMTU_FLOOD_MAX_NODES)
		seen[(*n_seen)++] = id;
}

/* Set the L2 header for a clone to the node a FIB lookup resolved. The lookup
 * is issued directly rather than via fib_lookup_v{4,6}(): those request
 * BPF_FIB_LOOKUP_SKIP_NEIGH, and clone_redirect() needs the DMAC resolved. */
static __always_inline bool
pmtu_flood_l2(struct __ctx_buff *ctx, struct bpf_fib_lookup_padded *fib,
	      int fib_ret)
{
	__s8 ext_err = 0;

	if (fib_ret != BPF_FIB_LKUP_RET_SUCCESS && fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH)
		return false;
	return fib_store_l2(ctx, fib, true, fib_ret, fib->l.ifindex, &ext_err) == 0;
}
#endif /* !IS_BPF_XDP */

#ifdef ENABLE_IPV4

#ifndef IS_BPF_XDP
struct pmtu_flood_ctx {
	struct __ctx_buff *ctx;
	__u16 *seen;		/* -> per-CPU pmtu_flood_scratch.seen */
	__u32 n_seen;
	__be32 cur_daddr;	/* outer daddr currently written in the packet */
	__be32 local_ip;	/* a local node IP, if one was iterated */
	bool have_local;	/* deliver the original locally after the loop */
};

/* bpf_for_each_map_elem callback over cilium_node_map_v2: send one copy of the
 * ICMP to each IPv4 node. Must return 0 (continue) or 1 (stop) for the verifier.
 */
static long
pmtu_flood_node_cb(void *map __maybe_unused, const void *key,
		   const void *value, void *arg)
{
	struct pmtu_flood_ctx *fc = arg;
	const struct node_key *nk = key;
	const struct node_value *nv = value;
	struct bpf_fib_lookup_padded fib = {};
	__be32 node_ip;
	__wsum sum;
	int ret;

	if (!fc || !nk || !nv)
		return 1;
	if (nk->family != ENDPOINT_KEY_IPV4)
		return 0;
	if (nv->flags & NODE_F_REMOTE_CLUSTER)
		return 0;		/* the proxy runs in this cluster only */
	if (pmtu_flood_seen(fc->seen, fc->n_seen, nv->id))
		return 0;
	node_ip = nk->ip4.be32;
	if (!node_ip)
		return 0;

	fib.l.family = AF_INET;
	fib.l.ifindex = ctx_get_ifindex(fc->ctx);
	fib.l.ipv4_dst = node_ip;
	ret = (int)fib_lookup(fc->ctx, &fib.l, sizeof(fib.l), 0);
	if (ret == BPF_FIB_LKUP_RET_NOT_FWDED) {
		/* Not forwarded is either this host or an unreachable/blackholed
		 * route; only a host endpoint gets the original delivered locally
		 * (the Envoy connection may terminate here) instead of a clone. */
		const struct endpoint_info *ep = __lookup_ip4_endpoint(node_ip);

		if (!ep || !(ep->flags & ENDPOINT_F_HOST))
			return 0;
		fc->local_ip = node_ip;
		fc->have_local = true;
		pmtu_flood_mark(fc->seen, &fc->n_seen, nv->id);
		return 0;
	}
	if (!pmtu_flood_l2(fc->ctx, &fib, ret))
		return 0;

	/* Address the copy to this node. The outer ICMP checksum does not cover
	 * the IP header, so only the IP checksum changes. cur_daddr follows the
	 * address actually in the packet, even if the checksum fix failed. */
	ret = ipv4_l3_rewrite_addr(fc->ctx, ETH_HLEN, IPV4_DADDR_OFF, fc->cur_daddr,
				   node_ip, &sum);
	if (ret != DROP_WRITE_ERROR)
		fc->cur_daddr = node_ip;
	if (ret != 0)
		return 0;
	if (clone_redirect(fc->ctx, fib.l.ifindex, 0) == 0)
		pmtu_flood_mark(fc->seen, &fc->n_seen, nv->id);
	return 0;
}
#endif /* !IS_BPF_XDP */

/*
 * handle_icmp_svc_pmtu_v4 - relay an ICMPv4 frag-needed addressed to a service
 * VIP to the endpoint that must lower its PMTU.
 *
 * @l4_off: offset of the (outer) ICMP header.
 *
 * Returns CTX_ACT_REDIRECT (rewritten to the DSR backend; the caller recircles
 * it through from-netdev), CTX_ACT_OK (not ours / not applicable -> caller keeps
 * its default handling), or a DROP_* code.
 */
static __always_inline int
handle_icmp_svc_pmtu_v4(struct __ctx_buff *ctx, struct iphdr *ip4, int l4_off)
{
	__u32 inner_l3_off = (__u32)(l4_off + sizeof(struct icmphdr));
	struct icmphdr icmphdr __align_stack_8;
	struct iphdr inner;
	struct lb4_key key = {};
	const struct lb4_service *svc;
	const struct lb4_backend *backend;
	struct ipv4_ct_tuple tuple = {};
	__be16 ports[2];	/* embedded sport = svc_port, dport = client port */
	__be16 l4_csum = 0;
	__wsum outer_csum_diff;
	bool has_inner_l4_csum = true;
	__u32 backend_id, icmp_l4_off;
	int ret;

	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		return DROP_INVALID;
	if (icmphdr.type != ICMP_DEST_UNREACH || icmphdr.code != ICMP_FRAG_NEEDED)
		return CTX_ACT_OK;

	/* Inner packet = the original reply the backend sent:
	 * src = VIP:svc_port, dst = client:client_port. (RFC 5508)
	 */
	if (ctx_load_bytes(ctx, inner_l3_off, &inner, sizeof(inner)) < 0)
		return DROP_INVALID;

	/* Only the original error is handled: its outer destination is the VIP,
	 * which equals the embedded packet's source. Flooded L7 copies (below)
	 * carry a rewritten outer destination (a node IP), so they fall through
	 * here -- this is the loop guard for the flood. */
	if (ip4->daddr != inner.saddr)
		return CTX_ACT_OK;

	/* Only TCP/UDP services participate, and only a first fragment carries
	 * the embedded L4 ports. */
	if (inner.protocol != IPPROTO_TCP && inner.protocol != IPPROTO_UDP)
		return CTX_ACT_OK;
	if (!ipfrag_has_l4_header(ipfrag_encode_ipv4(&inner)))
		return CTX_ACT_OK;

	icmp_l4_off = inner_l3_off + ipv4_hdrlen(&inner);
	if (l4_load_ports(ctx, (int)icmp_l4_off, ports) < 0)
		return DROP_INVALID;

	key.address = inner.saddr;
	key.dport = ports[0];
	key.proto = inner.protocol;
	svc = lb4_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;			/* not a service VIP */

	/* L7/Ingress services (which also carry the DSR flag) terminate at a
	 * cilium-envoy proxy on one node; flood the error to every node so the
	 * owner's kernel caches the PMTU for its transparent socket. */
	if (lb4_svc_is_l7_loadbalancer(svc)) {
#ifndef IS_BPF_XDP
		struct pmtu_flood_ctx fc = {
			.ctx = ctx,
			.cur_daddr = inner.saddr,	/* == outer daddr (VIP) */
		};
		struct pmtu_flood_scratch *scratch;
		__u32 zero = 0;
		__wsum sum;

		scratch = map_lookup_elem(&cilium_pmtu_flood_scratch, &zero);
		if (!scratch)
			return CTX_ACT_OK;
		if (pmtu_relay_ratelimited(svc->rev_nat_index))
			return DROP_RATE_LIMITED;
		fc.seen = scratch->seen;

		for_each_map_elem(&cilium_node_map_v2, pmtu_flood_node_cb, &fc, 0);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

		/* Remote nodes got clones. If this node was iterated, hand the
		 * original to the local stack addressed to the local node IP (the
		 * loop left it pointing at the last remote node). */
		if (fc.have_local) {
			ret = ipv4_l3_rewrite_addr(ctx, ETH_HLEN, IPV4_DADDR_OFF,
						   fc.cur_daddr, fc.local_ip, &sum);
			if (IS_ERR(ret))
				return ret;
			return CTX_ACT_OK;
		}
		/* Original consumed; per-node copies were clone-redirected. */
		return DROP_PMTU_RELAYED;
#else
		/* The flood needs TC-only helpers. Hand the packet to TC without
		 * XFER_PKT_NO_SVC so its nodeport_lb4() reaches this hook again
		 * instead of skipping nodeport for it. */
		ctx_clear_xfer(ctx, XFER_PKT_NO_SVC);
		return CTX_ACT_OK;
#endif
	}

	/* L4 DSR: relay directly to the backend selected on this node. */
	if (!lb4_svc_uses_dsr(svc))
		return CTX_ACT_OK;			/* SNAT-mode: out of scope */

	/* Backend re-derivation must be deterministic across nodes: only the
	 * Maglev hash excludes the VIP, so the (arbitrary) node the ICMP lands on
	 * picks the same backend the ingress node did. Under any other algorithm
	 * (e.g. random) the re-derived backend would differ, so skip the relay. */
	if (lb_resolve_algorithm(lb4_algorithm(svc)) != LB_SELECTION_MAGLEV)
		return CTX_ACT_OK;

	/* Re-derive the same backend the ingress node picked. The Maglev hash
	 * is a pure function of (client addr, client port, svc port, proto) and
	 * excludes the VIP, so any node computes the same result.
	 *
	 * Tuple handedness matches lb4_local()'s call into
	 * lb4_select_backend_id_maglev(): there sport = tuple->dport,
	 * dport = tuple->sport, and the hash uses tuple->saddr. We therefore set
	 * saddr = client, sport = svc_port, dport = client_port so the hashed
	 * inputs equal the forward path's (saddr=client, sport=client_port,
	 * dport=svc_port after the port swap).
	 */
	tuple.saddr = inner.daddr;		/* client */
	tuple.daddr = inner.saddr;		/* VIP */
	tuple.nexthdr = inner.protocol;
	tuple.sport = ports[0];
	tuple.dport = ports[1];

	/* A sticky client may be pinned to a backend Maglev no longer maps it
	 * to; prefer the pin when this node holds it, as lb4_local() does. */
	backend_id = 0;
	if (lb4_svc_is_affinity(svc)) {
		union lb4_affinity_client_id client_id = {
			.client_ip = tuple.saddr,
		};

		backend_id = lb4_affinity_backend_id_peek(svc, &client_id);
	}
	if (!backend_id)
		backend_id = lb4_select_backend_id(ctx, &key, &tuple, svc);
	if (!backend_id)
		return CTX_ACT_OK;
	backend = __lb4_lookup_backend(backend_id);
	if (!backend)
		return CTX_ACT_OK;
#if DSR_ENCAP_MODE != DSR_ENCAP_NONE
	/* Backends behind DSR encapsulation are not natively routable from this
	 * node, so recircling can only deliver to a local backend. */
	if (!__lookup_ip4_endpoint(backend->address))
		return CTX_ACT_OK;
#endif

	if (pmtu_relay_ratelimited(svc->rev_nat_index))
		return DROP_RATE_LIMITED;

	/* Reverse the DSR DNAT on the embedded (inner) packet so the backend
	 * kernel matches the error to its socket (backend:backend_port <-> client):
	 * rewrite inner src VIP:svc_port -> backend->address:backend->port (fixing
	 * the inner IP + inner L4 checksums), then rewrite the OUTER dst VIP ->
	 * backend and amend the OUTER ICMP checksum for the embedded change. This
	 * mirrors snat_v4_rev_nat_handle_icmp_error() + snat_v4_rev_nat()'s two-step
	 * rewrite: fixing only the inner checksums leaves the outer ICMP checksum
	 * stale and the backend kernel silently drops the error.
	 *
	 * A frag-needed error may embed only the IP header + 8 L4 bytes, which is
	 * too short to carry the inner L4 checksum. */
	if (inner.protocol == IPPROTO_TCP &&
	    (__u32)ctx_full_len(ctx) - inner_l3_off <
	    ipv4_hdrlen(&inner) + TCP_CSUM_OFF + TCP_CSUM_SIZE)
		has_inner_l4_csum = false;

	/* For UDP a checksum of 0 means "no checksum"; treat it as absent so the
	 * outer ICMP diff accounts for the port change only (the address change
	 * is cancelled by the inner IP checksum). Matches
	 * snat_v4_rev_nat_handle_icmp_error(). */
	if (inner.protocol == IPPROTO_UDP) {
		if (udp_load_csum(ctx, (int)icmp_l4_off, &l4_csum) < 0)
			return DROP_INVALID;
		if (l4_csum == 0)
			has_inner_l4_csum = false;
	}

	outer_csum_diff = snat_v4_calc_icmp_error_csum_diff(inner.saddr,
							    backend->address,
							    ports[0], backend->port,
							    has_inner_l4_csum);

	/* (1) Rewrite the embedded packet. */
	ret = snat_v4_rewrite_headers(ctx, inner.protocol, (int)inner_l3_off,
				      true, (int)icmp_l4_off,
				      inner.saddr, backend->address, IPV4_SADDR_OFF,
				      ports[0], backend->port, TCP_SPORT_OFF, 0);
	if (!has_inner_l4_csum && ret == DROP_CSUM_L4)
		ret = 0;
	if (IS_ERR(ret))
		return ret;

	/* (2) Rewrite the outer IP dst VIP -> backend and amend the outer ICMP
	 * checksum. The old outer daddr == VIP == inner.saddr, a stack value (the
	 * packet pointer is stale after the write above). No outer port change. */
	ret = snat_v4_rewrite_headers(ctx, IPPROTO_ICMP, ETH_HLEN, true, l4_off,
				      inner.saddr, backend->address, IPV4_DADDR_OFF,
				      0, 0, 0, outer_csum_diff);
	if (IS_ERR(ret))
		return ret;

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

	/* The outer destination now points at the backend: the caller recircles
	 * through from-netdev, where normal pod routing delivers to the backend
	 * (local endpoint or remote node). */
	return CTX_ACT_REDIRECT;
}

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6

/*
 * IPv6 counterpart. The mechanics mirror the IPv4 path with two differences:
 *  - the trigger is ICMPv6 "packet too big" (ICMPV6_PKT_TOOBIG);
 *  - the ICMPv6 checksum has a pseudo-header, so every outer-address rewrite
 *    must amend it. snat_v6_rewrite_headers() does that (it applies the address
 *    diff at the ICMPv6 checksum offset with BPF_F_PSEUDO_HDR), so the outer
 *    destination is rewritten through it. The embedded rewrite needs no
 *    separate outer-checksum fix: IPv6 has no L3 checksum, so the embedded
 *    address change and the embedded L4 checksum change cancel out in the
 *    enclosing ICMPv6 checksum (as in snat_v6_rev_nat_handle_icmp_pkt_toobig()).
 */
#ifndef IS_BPF_XDP
struct pmtu_flood_ctx6 {
	struct __ctx_buff *ctx;
	__u16 *seen;		/* -> per-CPU pmtu_flood_scratch.seen */
	__u32 n_seen;
	union v6addr cur_daddr;	/* outer daddr currently written in the packet */
	union v6addr local_ip;	/* a local node IP, if one was iterated */
	int l4_off;		/* outer ICMPv6 header, for the pseudo-header csum */
	bool have_local;	/* deliver the original locally after the loop */
};

static long
pmtu_flood_node_cb6(void *map __maybe_unused, const void *key,
		    const void *value, void *arg)
{
	struct pmtu_flood_ctx6 *fc = arg;
	const struct node_key *nk = key;
	const struct node_value *nv = value;
	struct bpf_fib_lookup_padded fib = {};
	union v6addr node_ip;
	int ret;

	if (!fc || !nk || !nv)
		return 1;
	if (nk->family != ENDPOINT_KEY_IPV6)
		return 0;
	if (nv->flags & NODE_F_REMOTE_CLUSTER)
		return 0;
	if (pmtu_flood_seen(fc->seen, fc->n_seen, nv->id))
		return 0;
	node_ip = nk->ip6;

	fib.l.family = AF_INET6;
	fib.l.ifindex = ctx_get_ifindex(fc->ctx);
	ipv6_addr_copy((union v6addr *)&fib.l.ipv6_dst, &node_ip);
	ret = (int)fib_lookup(fc->ctx, &fib.l, sizeof(fib.l), 0);
	if (ret == BPF_FIB_LKUP_RET_NOT_FWDED) {
		const struct endpoint_info *ep = __lookup_ip6_endpoint(&node_ip);

		if (!ep || !(ep->flags & ENDPOINT_F_HOST))
			return 0;
		fc->local_ip = node_ip;
		fc->have_local = true;
		pmtu_flood_mark(fc->seen, &fc->n_seen, nv->id);
		return 0;
	}
	if (!pmtu_flood_l2(fc->ctx, &fib, ret))
		return 0;

	/* Address the copy to this node and amend the ICMPv6 checksum for the
	 * pseudo-header change. */
	if (snat_v6_rewrite_headers(fc->ctx, IPPROTO_ICMPV6, ETH_HLEN, true,
				    fc->l4_off, &fc->cur_daddr, &node_ip,
				    IPV6_DADDR_OFF, 0, 0, 0, 0) < 0)
		return 0;
	fc->cur_daddr = node_ip;
	if (clone_redirect(fc->ctx, fib.l.ifindex, 0) == 0)
		pmtu_flood_mark(fc->seen, &fc->n_seen, nv->id);
	return 0;
}
#endif /* !IS_BPF_XDP */

static __always_inline int
handle_icmp_svc_pmtu_v6(struct __ctx_buff *ctx, struct ipv6hdr *ip6, int l4_off)
{
	__u32 inner_l3_off = (__u32)(l4_off + sizeof(struct icmp6hdr));
	struct ipv6hdr inner;
	struct lb6_key key = {};	/* key.address == the VIP */
	const struct lb6_service *svc;
	const struct lb6_backend *backend;
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	union v6addr backend_addr;
	__be16 ports[2];	/* embedded sport = svc_port, dport = client port */
	__be16 l4_csum = 0;
	__u8 inner_nexthdr, type;
	__u32 backend_id, icmp_l4_off;
	fraginfo_t fraginfo;
	int hdrlen, ret;

	if (icmp6_load_type(ctx, l4_off, &type) < 0)
		return DROP_INVALID;
	if (type != ICMPV6_PKT_TOOBIG)
		return CTX_ACT_OK;

	/* Inner packet = the original reply: src = VIP:svc_port, dst = client. */
	if (ctx_load_bytes(ctx, inner_l3_off, &inner, sizeof(inner)) < 0)
		return DROP_INVALID;

	/* Loop guard: only the original error, addressed to the VIP that sourced
	 * the embedded packet (see the IPv4 path). */
	if (!ipv6_addr_equals((union v6addr *)&ip6->daddr,
			      (union v6addr *)&inner.saddr))
		return CTX_ACT_OK;

	inner_nexthdr = inner.nexthdr;
	hdrlen = ipv6_hdrlen_offset(ctx, (int)inner_l3_off, &inner_nexthdr,
				    &fraginfo);
	if (hdrlen < 0)
		return DROP_INVALID;
	icmp_l4_off = inner_l3_off + (__u32)hdrlen;

	if (inner_nexthdr != IPPROTO_TCP && inner_nexthdr != IPPROTO_UDP)
		return CTX_ACT_OK;
	if (!ipfrag_has_l4_header(fraginfo))
		return CTX_ACT_OK;
	if (l4_load_ports(ctx, (int)icmp_l4_off, ports) < 0)
		return DROP_INVALID;

	ipv6_addr_copy(&key.address, (union v6addr *)&inner.saddr);
	key.dport = ports[0];
	key.proto = inner_nexthdr;
	svc = lb6_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;

	/* L7/Ingress: flood the error to every node (see the IPv4 path). */
	if (lb6_svc_is_l7_loadbalancer(svc)) {
#ifndef IS_BPF_XDP
		struct pmtu_flood_ctx6 fc = {
			.ctx = ctx,
			.l4_off = l4_off,
		};
		struct pmtu_flood_scratch *scratch;
		__u32 zero = 0;

		scratch = map_lookup_elem(&cilium_pmtu_flood_scratch, &zero);
		if (!scratch)
			return CTX_ACT_OK;
		if (pmtu_relay_ratelimited(svc->rev_nat_index))
			return DROP_RATE_LIMITED;
		fc.seen = scratch->seen;
		ipv6_addr_copy(&fc.cur_daddr, &key.address);

		for_each_map_elem(&cilium_node_map_v2, pmtu_flood_node_cb6, &fc, 0);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

		if (fc.have_local) {
			ret = snat_v6_rewrite_headers(ctx, IPPROTO_ICMPV6, ETH_HLEN,
						      true, l4_off, &fc.cur_daddr,
						      &fc.local_ip, IPV6_DADDR_OFF,
						      0, 0, 0, 0);
			if (IS_ERR(ret))
				return ret;
			return CTX_ACT_OK;
		}
		return DROP_PMTU_RELAYED;
#else
		/* TC-only flood; see the IPv4 path. */
		ctx_clear_xfer(ctx, XFER_PKT_NO_SVC);
		return CTX_ACT_OK;
#endif
	}

	if (!lb6_svc_uses_dsr(svc))
		return CTX_ACT_OK;			/* SNAT-mode: out of scope */

	/* Only Maglev re-derives the same backend on any node (see IPv4 path). */
	if (lb_resolve_algorithm(lb6_algorithm(svc)) != LB_SELECTION_MAGLEV)
		return CTX_ACT_OK;

	/* Rewriting the embedded packet keeps the outer ICMPv6 checksum valid only
	 * because the embedded address change and the embedded L4 checksum change
	 * cancel (IPv6 has no L3 checksum). A UDP reply with checksum 0 ("no
	 * checksum") has no L4 checksum to cancel the address/port change, so the
	 * rewrite would leave the outer ICMPv6 checksum wrong and the backend would
	 * drop the relayed error. Don't emit a malformed error for that rare case;
	 * leave it to the stack. Likewise when the error embeds only the first 8
	 * L4 bytes: the embedded TCP checksum is absent. */
	if (inner_nexthdr == IPPROTO_UDP) {
		if (udp_load_csum(ctx, (int)icmp_l4_off, &l4_csum) < 0)
			return DROP_INVALID;
		if (l4_csum == 0)
			return CTX_ACT_OK;
	}
	if (inner_nexthdr == IPPROTO_TCP &&
	    (__u32)ctx_full_len(ctx) - inner_l3_off <
	    (__u32)hdrlen + TCP_CSUM_OFF + TCP_CSUM_SIZE)
		return CTX_ACT_OK;

	/* Re-derive the backend statelessly (Maglev; see the IPv4 path). */
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&inner.daddr);	/* client */
	ipv6_addr_copy(&tuple.daddr, &key.address);			/* VIP */
	tuple.nexthdr = inner_nexthdr;
	tuple.sport = ports[0];
	tuple.dport = ports[1];

	/* Prefer the affinity pin when this node holds it (see the IPv4 path). */
	backend_id = 0;
	if (lb6_svc_is_affinity(svc)) {
		union lb6_affinity_client_id client_id;

		ipv6_addr_copy(&client_id.client_ip, &tuple.saddr);
		backend_id = lb6_affinity_backend_id_peek(svc, &client_id);
	}
	if (!backend_id)
		backend_id = lb6_select_backend_id(ctx, &key, &tuple, svc);
	if (!backend_id)
		return CTX_ACT_OK;
	backend = __lb6_lookup_backend(backend_id);
	if (!backend)
		return CTX_ACT_OK;
	ipv6_addr_copy(&backend_addr, (union v6addr *)&backend->address);
#if DSR_ENCAP_MODE != DSR_ENCAP_NONE
	if (!__lookup_ip6_endpoint(&backend_addr))
		return CTX_ACT_OK;	/* see the IPv4 path */
#endif

	if (pmtu_relay_ratelimited(svc->rev_nat_index))
		return DROP_RATE_LIMITED;

	/* (1) Rewrite the embedded packet: inner src VIP:svc_port -> backend.
	 * The embedded L4 checksum is fixed; the outer ICMPv6 checksum is left
	 * unchanged (the inner address and inner L4 checksum changes cancel). */
	ret = snat_v6_rewrite_headers(ctx, inner_nexthdr, (int)inner_l3_off, true,
				      (int)icmp_l4_off, &key.address, &backend_addr,
				      IPV6_SADDR_OFF, ports[0], backend->port,
				      TCP_SPORT_OFF, 0);
	if (IS_ERR(ret))
		return ret;

	/* (2) Rewrite the outer dst VIP -> backend and amend the ICMPv6 checksum
	 * for the address change. The old outer daddr == VIP == key.address, a
	 * stack value. */
	ret = snat_v6_rewrite_headers(ctx, IPPROTO_ICMPV6, ETH_HLEN, true, l4_off,
				      &key.address, &backend_addr, IPV6_DADDR_OFF,
				      0, 0, 0, 0);
	if (IS_ERR(ret))
		return ret;

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);
	return CTX_ACT_REDIRECT;
}

#endif /* ENABLE_IPV6 */

#else /* !(ENABLE_SVC_ICMP_PMTU_RELAY && (IS_BPF_HOST || IS_BPF_XDP)) */

static __always_inline int
handle_icmp_svc_pmtu_v4(struct __ctx_buff *ctx __maybe_unused,
			struct iphdr *ip4 __maybe_unused, int l4_off __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline int
handle_icmp_svc_pmtu_v6(struct __ctx_buff *ctx __maybe_unused,
			struct ipv6hdr *ip6 __maybe_unused, int l4_off __maybe_unused)
{
	return CTX_ACT_OK;
}

#endif /* ENABLE_SVC_ICMP_PMTU_RELAY && (IS_BPF_HOST || IS_BPF_XDP) */
