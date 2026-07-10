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
 * This helper intercepts those errors on the forward path (nodeport_lb4) and
 * relays them to the backend that owns the connection:
 *
 *   - DSR backend: re-derive the owning backend statelessly via the same Maglev
 *     hash used on the forward path (the hash excludes the VIP, so any node
 *     derives the same backend), rewrite the error to that backend and forward
 *     it there. The backend's kernel caches the reduced PMTU for the connection.
 *     This is stateless, so it works even when BGP/ECMP lands the error on a
 *     node that is not the one holding the flow.
 *
 *   - SNAT-mode backend: the backend was chosen statefully on the ingress node
 *     and only that node holds the service conntrack entry, so recovery is
 *     best-effort: the backend is read from the CT_SERVICE entry and the relay
 *     only fires when the error came back to the ingress node (common for
 *     single-entry / tunnel topologies). Under ECMP the error usually lands on
 *     another node, where no CT entry exists and the relay falls through.
 *
 *   - L7/Ingress (Envoy): the connection terminates at a cilium-envoy proxy on
 *     one node and cannot be re-derived statelessly, so flood the error to every
 *     node (with a per-CPU dedup set) with the outer destination rewritten to
 *     each node's IP. Only the node holding the transparent socket matches the
 *     embedded packet and caches the PMTU. TC path only.
 *
 * On a DSR/SNAT success the helper rewrites the embedded packet and the outer
 * destination to the backend and returns CTX_ACT_REDIRECT; the caller delivers
 * it (recircle for a local/native backend, encapsulate for a remote backend in
 * tunnel mode). The L7 flood consumes the original (DROP_PMTU_RELAYED) after
 * cloning it to each node. No per-connection PMTU state is stored in the
 * datapath.
 */

#pragma once

#include "common.h"
#include "lb.h"
#include "nat.h"
#include "conntrack.h"
#include "node.h"
#include "fib.h"
#include "eth.h"

#ifdef ENABLE_IPV6
#include "ipv6.h"
#include "icmp6.h"
#endif

#ifdef ENABLE_SVC_ICMP_PMTU_RELAY

/* Bound the relay per service (rev_nat_index) so a spoofed frag-needed spray at
 * a VIP cannot amplify. 100 relayed errors/s per service, burstable to 1000, is
 * far above the handful a real connection produces at PMTU-discovery time.
 * Returns true to drop. */
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

/* The L7 flood (both families) uses clone_redirect()/fib_lookup(), which are
 * TC-only helpers and only run on the TC bpf_host from-netdev path; compile it
 * out for XDP.
 *
 * cilium_node_map_v2 is keyed per node *IP*, so a node contributes several
 * entries (InternalIP, CiliumInternalIP, ...). Track the node IDs already
 * flooded so each node is sent one copy. The set is bounded; on clusters with
 * more than PMTU_FLOOD_MAX_NODES nodes the tail may receive duplicate (but
 * harmless -- PMTU caching is idempotent) copies.
 */
#ifndef IS_BPF_XDP
#define PMTU_FLOOD_MAX_NODES 64

/* Upper bound on how many backends a single service's error is flooded to (see
 * pmtu_flood_backends_v4/v6). Services with more backends than this have their
 * tail skipped; a connection whose backend is past the cap is not recovered.
 * bpf_loop iterates one body, so this only bounds the runtime loop, not the
 * program size. */
#define PMTU_FLOOD_MAX_BACKENDS 64

/* Per-CPU scratch for the flood dedup set. Kept off the BPF stack: a 128-byte
 * seen[] embedded in the on-stack flood context makes the compiler emit a
 * whole-struct __builtin_memset() to zero-initialise it, which BPF builtins.h
 * forbids (and which is too large for __bpf_memzero()). Map memory is always
 * defined for the verifier, so the flood only has to reset n_seen -- never zero
 * the array -- and it saves the stack space too. */
struct pmtu_flood_scratch {
	__u16 seen[PMTU_FLOOD_MAX_NODES];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct pmtu_flood_scratch);
	__uint(max_entries, 1);
} cilium_pmtu_flood_scratch __section_maps_btf;

/* Returns true if this node id was already flooded; otherwise records it. */
static __always_inline bool
pmtu_flood_seen(__u16 *seen, __u32 *n_seen, __u16 id)
{
	__u32 i;

	if (!id)
		return false;
	for (i = 0; i < PMTU_FLOOD_MAX_NODES; i++) {
		if (i >= *n_seen)
			break;
		if (seen[i] == id)
			return true;
	}
	if (*n_seen < PMTU_FLOOD_MAX_NODES)
		seen[(*n_seen)++] = id;
	return false;
}
#endif /* !IS_BPF_XDP */

#ifdef ENABLE_IPV4

/* Returns true for the ICMPv4 error types that carry a PMTU signal. */
static __always_inline bool
icmp4_is_frag_needed(__u8 type, __u8 code)
{
	return type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED;
}

/* Does the embedded (offending) packet still carry an L4 checksum we must
 * preserve? A frag-needed may embed only the IP header + 8 L4 bytes, too short
 * for the TCP checksum; and a UDP checksum of 0 means "no checksum". In both
 * cases the outer ICMP diff must account for the port change only. */
static __always_inline int
pmtu_inner_has_l4_csum_v4(struct __ctx_buff *ctx, __u8 proto, int inner_hdrlen,
			  __u32 total_inner_len, __u32 icmp_l4_off, bool *has_csum)
{
	*has_csum = true;

	if (proto == IPPROTO_TCP &&
	    total_inner_len < (__u32)inner_hdrlen + TCP_CSUM_OFF + sizeof(__u16))
		*has_csum = false;

	if (proto == IPPROTO_UDP) {
		__be16 l4_csum = 0;

		if (ctx_load_bytes(ctx, (int)(icmp_l4_off + offsetof(struct udphdr, check)),
				   &l4_csum, sizeof(l4_csum)) < 0)
			return DROP_INVALID;
		if (l4_csum == 0)
			*has_csum = false;
	}
	return 0;
}

/* Reverse the DSR DNAT on the embedded packet and re-address the error to a
 * backend: rewrite the embedded src old_addr:old_port -> new_addr:new_port
 * (fixing the inner IP + L4 checksums), then rewrite the OUTER dst old_addr ->
 * new_addr and amend the OUTER ICMP checksum for the embedded change. Fixing
 * only the inner checksums leaves the outer ICMP checksum stale and the backend
 * kernel silently drops the error. old_addr == the address currently in both
 * the embedded src and the outer dst (VIP on the first hop; the previous
 * backend when re-addressing a flood copy). */
static __always_inline int
pmtu_rewrite_to_backend_v4(struct __ctx_buff *ctx, __u8 proto, __u32 inner_l3_off,
			   __u32 icmp_l4_off, int l4_off, __be32 old_addr,
			   __be32 new_addr, __be16 old_port, __be16 new_port,
			   bool has_inner_l4_csum)
{
	__wsum outer_csum_diff = 0;
	int ret;

	snat_v4_calc_icmp_error_csum_diff(old_addr, new_addr, old_port, new_port,
					  has_inner_l4_csum, &outer_csum_diff);

	ret = snat_v4_rewrite_headers(ctx, proto, (int)inner_l3_off, true,
				      (int)icmp_l4_off,
				      old_addr, new_addr, IPV4_SADDR_OFF,
				      old_port, new_port, TCP_SPORT_OFF, 0);
	if (!has_inner_l4_csum && ret == DROP_CSUM_L4)
		ret = 0;
	if (IS_ERR(ret))
		return ret;

	return snat_v4_rewrite_headers(ctx, IPPROTO_ICMP, ETH_HLEN, true,
				       (int)l4_off,
				       old_addr, new_addr, IPV4_DADDR_OFF,
				       0, 0, 0, outer_csum_diff);
}

#ifndef IS_BPF_XDP
struct pmtu_flood_ctx {
	struct __ctx_buff *ctx;
	__u16 *seen;		/* -> per-CPU pmtu_flood_scratch.seen */
	__be32 cur_daddr;	/* outer daddr currently written in the packet */
	__be32 local_ip;	/* set to a local node IP: deliver the original locally */
	__u32 n_seen;
};

/* Resolve L2 for dst_ip and clone-redirect a copy of the current packet there.
 * Returns 1 if dst_ip is *this* node (fib NOT_FWDED) so the caller can deliver
 * the original locally instead; 0 otherwise (delivered, unresolved, or error --
 * the flood is best-effort per destination). */
static __always_inline int
pmtu_clone_redirect_v4(struct __ctx_buff *ctx, __be32 dst_ip)
{
	struct bpf_fib_lookup_padded fib = {};
	int ret, oif;

	fib.l.family = AF_INET;
	fib.l.ipv4_dst = dst_ip;
	fib.l.ifindex = ctx_get_ifindex(ctx);
	ret = (int)fib_lookup(ctx, &fib.l, sizeof(fib.l), 0);
	if (ret == BPF_FIB_LKUP_RET_NOT_FWDED)
		return 1;		/* destination is the local node */
	if (ret != BPF_FIB_LKUP_RET_SUCCESS && ret != BPF_FIB_LKUP_RET_NO_NEIGH)
		return 0;
	oif = fib.l.ifindex;
	if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
		if (eth_store_daddr(ctx, fib.l.dmac, 0) < 0)
			return 0;
		if (eth_store_saddr(ctx, fib.l.smac, 0) < 0)
			return 0;
	} else {
		/* Route known but neighbor unresolved: resolve the DMAC from the
		 * neigh map (as fib_do_redirect does) instead of skipping the
		 * destination, which would leave it without the PMTU copy. */
		const union macaddr *smac = device_mac(oif);
		const union macaddr *dmac = neigh_lookup_ip4(&dst_ip);

		if (!dmac)
			return 0;
		if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
			return 0;
		if (eth_store_saddr_aligned(ctx, smac->addr, 0) < 0)
			return 0;
	}
	clone_redirect(ctx, oif, 0);
	return 0;
}

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
	__be32 node_ip;

	if (!fc || !nk || !nv)
		return 1;
	if (nk->family != ENDPOINT_KEY_IPV4)
		return 0;		/* IPv4 nodes only for now */
	if (pmtu_flood_seen(fc->seen, &fc->n_seen, nv->id))
		return 0;		/* already flooded to this node */
	node_ip = nk->ip4.be32;
	if (!node_ip || node_ip == fc->cur_daddr)
		return 0;

	/* Rewrite the outer destination to this node's IP so its kernel accepts
	 * and processes the ICMP error locally. Fix the outer IP checksum
	 * incrementally (old = the daddr currently in the packet). The outer ICMP
	 * checksum does not cover the outer IP addresses, so it is unaffected.
	 */
	if (ctx_store_bytes(fc->ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
			    &node_ip, 4, 0) < 0)
		return 0;
	if (ipv4_csum_update_by_value(fc->ctx, ETH_HLEN, fc->cur_daddr,
				      node_ip, 4) < 0)
		return 0;
	fc->cur_daddr = node_ip;

	/* Destination is *this* node (the one the ICMP landed on). Don't
	 * clone-redirect a local IP; instead remember it so the caller delivers
	 * the original to the local host stack — the Envoy connection may be
	 * terminated here. */
	if (pmtu_clone_redirect_v4(fc->ctx, node_ip))
		fc->local_ip = node_ip;
	return 0;
}

/* The DSR backend flood iterates the service's backends with bpf_loop(), which
 * needs kernel >= 5.17. HAVE_LOOP is probed at agent startup (see probes.go); on
 * older kernels the flood is compiled out and non-Maglev DSR falls back to the
 * previous behavior (the error is not relayed). */
#ifdef HAVE_LOOP
/* State threaded through the DSR backend flood (bpf_loop callback). */
struct pmtu_backend_flood_ctx {
	struct __ctx_buff *ctx;
	struct lb4_key key;	/* address = VIP, dport = svc_port; slot mutated */
	__be32 cur_addr;	/* address currently written (VIP, then last backend) */
	int l4_off;
	__u32 inner_l3_off;
	__u32 icmp_l4_off;
	__be16 cur_port;
	__u8 inner_proto;
	bool has_inner_l4_csum;
	int err;		/* first rewrite error, propagated out of the loop */
};

/* bpf_loop callback: re-address the error to backend slot (index + 1) and
 * clone-redirect a copy to it. Returns 1 (stop) only on a hard rewrite error. */
static long
pmtu_flood_backend_cb_v4(__u32 index, void *arg)
{
	struct pmtu_backend_flood_ctx *bc = arg;
	const struct lb4_service *be_slot;
	const struct lb4_backend *backend;
	int ret;

	bc->key.backend_slot = (__u16)(index + 1);
	be_slot = __lb4_lookup_backend_slot(&bc->key);
	if (!be_slot || !be_slot->backend_id)
		return 0;
	backend = __lb4_lookup_backend(be_slot->backend_id);
	if (!backend || backend->address == bc->cur_addr)
		return 0;		/* missing, or already addressed here */

	ret = pmtu_rewrite_to_backend_v4(bc->ctx, bc->inner_proto, bc->inner_l3_off,
					 bc->icmp_l4_off, bc->l4_off, bc->cur_addr,
					 backend->address, bc->cur_port,
					 backend->port, bc->has_inner_l4_csum);
	if (IS_ERR(ret)) {
		bc->err = ret;
		return 1;
	}
	bc->cur_addr = backend->address;
	bc->cur_port = backend->port;

	pmtu_clone_redirect_v4(bc->ctx, backend->address);
	return 0;
}

/* Non-Maglev DSR: the backend cannot be re-derived statelessly (only the Maglev
 * hash excludes the VIP), so copy the error to EVERY backend of the service. The
 * backend that owns the flow matches it to its socket and caches the reduced
 * PMTU; the rest get an error for a connection they do not have and ignore it.
 * This is the CFP #19720 "copy to all endpoints" approach, applied to the DSR
 * backends. TC path only (clone_redirect). Best-effort over an overlay: a remote
 * backend in tunnel mode needs encapsulation that clone_redirect does not add.
 * Consumes the original (each backend received a clone). */
static __always_inline int
pmtu_flood_backends_v4(struct __ctx_buff *ctx, const struct lb4_service *svc,
		       const struct lb4_key *key, int l4_off, __u32 inner_l3_off,
		       __u32 icmp_l4_off, __be32 vip, __be16 svc_port,
		       __u8 inner_proto, int inner_hdrlen)
{
	struct pmtu_backend_flood_ctx bc = {
		.ctx		= ctx,
		.key		= *key,
		.cur_addr	= vip,
		.cur_port	= svc_port,
		.l4_off		= l4_off,
		.inner_l3_off	= inner_l3_off,
		.icmp_l4_off	= icmp_l4_off,
		.inner_proto	= inner_proto,
	};
	__u32 total_inner_len = (__u32)ctx_full_len(ctx) - inner_l3_off;
	__u32 nr = svc->count;
	int ret;

	ret = pmtu_inner_has_l4_csum_v4(ctx, inner_proto, inner_hdrlen,
					total_inner_len, icmp_l4_off,
					&bc.has_inner_l4_csum);
	if (ret < 0)
		return ret;

	if (nr > PMTU_FLOOD_MAX_BACKENDS)
		nr = PMTU_FLOOD_MAX_BACKENDS;
	loop(nr, pmtu_flood_backend_cb_v4, &bc, 0);
	if (IS_ERR(bc.err))
		return bc.err;

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);
	return DROP_PMTU_RELAYED;
}
#endif /* HAVE_LOOP */
#endif /* !IS_BPF_XDP */

/*
 * handle_icmp_svc_pmtu_v4 - relay an ICMPv4 frag-needed addressed to a service
 * VIP to the endpoint that must lower its PMTU (DSR/SNAT backend, or all nodes
 * for L7/Ingress). See the file header for the per-mode strategy.
 *
 * @l4_off: offset of the (outer) ICMP header.
 *
 * Returns CTX_ACT_REDIRECT (DSR/SNAT: rewritten to the backend), CTX_ACT_OK
 * (not ours / not applicable -> caller keeps its default handling), or a
 * negative code (DROP_PMTU_RELAYED after an L7 flood, or a DROP_* error).
 */
static __always_inline int
handle_icmp_svc_pmtu_v4(struct __ctx_buff *ctx, struct iphdr *ip4, int l4_off,
			__s8 *ext_err __maybe_unused)
{
	__u32 inner_l3_off = (__u32)(l4_off + sizeof(struct icmphdr));
	struct icmphdr icmphdr __align_stack_8;
	struct iphdr inner;
	struct lb4_key key = {};
	const struct lb4_service *svc;
	const struct lb4_backend *backend;
	struct ipv4_ct_tuple tuple = {};
	__be16 svc_port = 0, client_port = 0;
	__u32 backend_id;
	__u32 icmp_l4_off;
	int ret;

	if (ip4->protocol != IPPROTO_ICMP)
		return CTX_ACT_OK;

	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		return DROP_INVALID;
	if (!icmp4_is_frag_needed(icmphdr.type, icmphdr.code))
		return CTX_ACT_OK;

	/* Inner packet = the original reply the backend sent:
	 * src = VIP:svc_port, dst = client:client_port. (RFC 5508)
	 */
	if (ctx_load_bytes(ctx, inner_l3_off, &inner, sizeof(inner)) < 0)
		return DROP_INVALID;

	/* Only TCP/UDP services participate. */
	switch (inner.protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;
	default:
		return CTX_ACT_OK;
	}

	icmp_l4_off = inner_l3_off + ipv4_hdrlen(&inner);
	/* Inner L4 ports: sport = svc_port (from the VIP side), dport = client. */
	if (ctx_load_bytes(ctx, icmp_l4_off, &svc_port, sizeof(svc_port)) < 0)
		return DROP_INVALID;
	if (ctx_load_bytes(ctx, icmp_l4_off + 2, &client_port, sizeof(client_port)) < 0)
		return DROP_INVALID;

	/* Service lookup keyed on the inner packet's VIP:svc_port. */
	key.address = inner.saddr;
	key.dport = svc_port;
	key.proto = inner.protocol;

	/* Only an error addressed to the VIP is handled: its outer destination is
	 * the VIP, which equals the embedded packet's source. */
	if (ip4->daddr != inner.saddr)
		return CTX_ACT_OK;

	svc = lb4_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;			/* not a service VIP */
	if (pmtu_relay_ratelimited(svc->rev_nat_index))
		return DROP_RATE_LIMITED;

	/* L7/Ingress services (which also carry the DSR flag) terminate at a
	 * cilium-envoy proxy on one node; the backend the datapath would resolve
	 * is not where the connection lives, so flood the error to every node so
	 * the owner's kernel caches the PMTU for its transparent socket. */
	if (lb4_svc_is_l7_loadbalancer(svc)) {
#ifndef IS_BPF_XDP
		struct pmtu_flood_ctx fc = {};
		struct pmtu_flood_scratch *scratch;
		__u32 zero = 0;

		/* Borrow the per-CPU dedup scratch (see the IPv6 path); the seen[]
		 * pointer is read only for indices < n_seen, which are written before
		 * use, so its stale contents are irrelevant. */
		scratch = map_lookup_elem(&cilium_pmtu_flood_scratch, &zero);
		if (!scratch)
			return CTX_ACT_OK;
		fc.ctx = ctx;
		fc.seen = scratch->seen;
		fc.cur_daddr = inner.saddr;	/* == current outer daddr (VIP) */
		/* local_ip and n_seen are left zero by the initialiser. */

		for_each_map_elem(&cilium_node_map_v2, pmtu_flood_node_cb, &fc, 0);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

		/* Remote nodes were reached via clone_redirect. If one of the nodes
		 * is the local node (the ICMP landed here), deliver the original to
		 * the local host stack too: rewrite its outer dst to the local node
		 * IP (the loop left it pointing at the last remote node) and let it
		 * continue up the stack so a locally-terminated Envoy connection
		 * caches the PMTU. */
		if (fc.local_ip) {
			if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
					    &fc.local_ip, 4, 0) < 0)
				return DROP_WRITE_ERROR;
			if (ipv4_csum_update_by_value(ctx, ETH_HLEN, fc.cur_daddr,
						      fc.local_ip, 4) < 0)
				return DROP_CSUM_L3;
			return CTX_ACT_OK;
		}
		/* Original consumed; per-node copies were clone-redirected. */
		return DROP_PMTU_RELAYED;
#else
		return CTX_ACT_OK;		/* L7 relay is TC-only */
#endif
	}

	/* Build the flow tuple once; both the DSR and SNAT paths key on it.
	 *
	 * Handedness matches lb4_local() / lb4_select_backend_id_maglev(): the
	 * ports are stored swapped (sport = svc_port, dport = client_port) and the
	 * hash uses tuple->saddr = client. This equals the forward path's tuple
	 * (saddr = client, sport = client_port, dport = svc_port before the swap),
	 * so the Maglev result and the CT_SERVICE key both match the ingress node.
	 */
	tuple.saddr = inner.daddr;		/* client */
	tuple.daddr = inner.saddr;		/* VIP */
	tuple.nexthdr = inner.protocol;
	tuple.sport = svc_port;
	tuple.dport = client_port;

	if (svc->flags2 & SVC_FLAG_FWD_MODE_DSR) {
		/* DSR: re-derive the backend statelessly. Only the Maglev hash
		 * excludes the VIP, so the (arbitrary) node the ICMP lands on picks
		 * the same backend the ingress node did. Under any other algorithm
		 * the re-derived backend would differ, so instead of re-deriving we
		 * flood the error to every backend of the service (below).
		 *
		 * Resolve the effective algorithm exactly as lb4_select_backend_id()
		 * does (per-service value, falling back to the default) so this check
		 * tracks the real backend selection rather than a compile-time
		 * assumption. */
		__u32 alg = lb4_algorithm(svc);

		if (alg != LB_SELECTION_MAGLEV && alg != LB_SELECTION_RANDOM &&
		    alg != LB_SELECTION_FIRST)
			alg = lb_default_algorithm();
		if (alg != LB_SELECTION_MAGLEV) {
#if !defined(IS_BPF_XDP) && defined(HAVE_LOOP)
			/* Non-Maglev DSR: copy the error to all backends (the one
			 * owning the flow caches the PMTU, the rest ignore it). */
			return pmtu_flood_backends_v4(ctx, svc, &key, l4_off,
						      inner_l3_off, icmp_l4_off,
						      inner.saddr, svc_port,
						      inner.protocol,
						      ipv4_hdrlen(&inner));
#else
			/* flood is TC-only and needs bpf_loop (HAVE_LOOP) */
			return CTX_ACT_OK;
#endif
		}
		backend_id = lb4_select_backend_id(ctx, &key, &tuple, svc);
	} else {
		/* SNAT-mode: the backend was chosen statefully on the ingress node
		 * and only that node holds the service conntrack entry, so this is
		 * best-effort -- it can only relay when the error came back to the
		 * ingress node (typical for single-entry / tunnel topologies; never
		 * under ECMP, where the error lands elsewhere and we fall through).
		 * Recover the backend by repeating lb4_local()'s CT_SERVICE lookup
		 * with the same tuple, so the key matches; the embedded reply's L4
		 * header sits at icmp_l4_off. */
		/* rev_nat_index must be set for the CT_SERVICE match (see
		 * ct_entry_matches_types()); lb4_local() sets it before the lookup. */
		struct ct_state ct_state = { .rev_nat_index = svc->rev_nat_index };
		__u32 monitor = 0;

		/* We already parsed the ports into the tuple, so tell CT not to read
		 * the embedded L4 header (it may be truncated in the ICMP payload):
		 * this is a pure, side-effect-free key lookup. */
		ret = ct_lazy_lookup4(get_ct_map4(&tuple), &tuple, ctx,
				      IPFRAG_BIT_NO_L4_HEADER, (int)icmp_l4_off,
				      CT_SERVICE, SCOPE_REVERSE, CT_ENTRY_SVC,
				      &ct_state, &monitor);
		if (ret != CT_REPLY)
			return CTX_ACT_OK;	/* no local CT entry: not the ingress node */
		backend_id = ct_state.backend_id;
	}

	if (!backend_id)
		return CTX_ACT_OK;
	backend = __lb4_lookup_backend(backend_id);
	if (!backend)
		return CTX_ACT_OK;

	/* Reverse the DSR DNAT on the embedded (inner) packet so the backend
	 * kernel matches the error to its socket (backend:backend_port <-> client),
	 * and re-address the outer error to the backend. This mirrors
	 * snat_v4_rev_nat_handle_icmp_error() + snat_v4_rev_nat()'s two-step rewrite
	 * (see pmtu_rewrite_to_backend_v4()).
	 */
	{
		__u32 total_inner_len = (__u32)ctx_full_len(ctx) - inner_l3_off;
		bool has_inner_l4_csum;

		ret = pmtu_inner_has_l4_csum_v4(ctx, inner.protocol, ipv4_hdrlen(&inner),
						total_inner_len, icmp_l4_off,
						&has_inner_l4_csum);
		if (ret < 0)
			return ret;

		ret = pmtu_rewrite_to_backend_v4(ctx, inner.protocol, inner_l3_off,
						 icmp_l4_off, l4_off, inner.saddr,
						 backend->address, svc_port,
						 backend->port, has_inner_l4_csum);
		if (IS_ERR(ret))
			return ret;
	}

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

	/* Delivery: the outer destination now points at the backend, so return
	 * CTX_ACT_REDIRECT and let the caller recircle through from-netdev, where
	 * normal pod routing delivers to the backend (local endpoint or remote
	 * node) without needing a backend-local vs -remote distinction here.
	 */
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
 *    destination is rewritten through it rather than by hand. The embedded
 *    rewrite needs no separate outer-checksum fix: IPv6 has no L3 checksum, so
 *    the embedded address change and the embedded L4 checksum change cancel out
 *    in the enclosing ICMPv6 checksum (same reasoning as the stock
 *    snat_v6_rev_nat_handle_icmp_pkt_toobig()).
 */

/* Re-address the error to a backend (IPv6): rewrite the embedded src
 * old_addr:old_port -> new_addr:new_port, then the outer dst old_addr -> new_addr
 * (snat_v6_rewrite_headers amends the ICMPv6 pseudo-header checksum). IPv6 has no
 * L3 checksum, so the embedded address and L4 checksum changes cancel in the
 * outer ICMPv6 checksum; no separate outer diff is needed. The caller must have
 * rejected the UDP-checksum-0 case first (see the file header). */
static __always_inline int
pmtu_rewrite_to_backend_v6(struct __ctx_buff *ctx, __u8 nexthdr, __u32 inner_l3_off,
			   __u32 icmp_l4_off, int l4_off, const union v6addr *old_addr,
			   const union v6addr *new_addr, __be16 old_port, __be16 new_port)
{
	int ret;

	ret = snat_v6_rewrite_headers(ctx, nexthdr, (int)inner_l3_off, true,
				      (int)icmp_l4_off, old_addr, new_addr,
				      IPV6_SADDR_OFF, old_port, new_port, TCP_SPORT_OFF);
	if (IS_ERR(ret))
		return ret;

	return snat_v6_rewrite_headers(ctx, IPPROTO_ICMPV6, ETH_HLEN, true, l4_off,
				       old_addr, new_addr, IPV6_DADDR_OFF, 0, 0, 0);
}

#ifndef IS_BPF_XDP
struct pmtu_flood_ctx6 {
	struct __ctx_buff *ctx;
	__u16 *seen;		/* -> per-CPU pmtu_flood_scratch.seen */
	union v6addr cur_daddr;	/* outer daddr currently written in the packet */
	union v6addr local_ip;	/* a local node IP, if one was iterated */
	int l4_off;		/* offset of the outer ICMPv6 header */
	bool have_local;
	__u32 n_seen;
};

/* IPv6 counterpart of pmtu_clone_redirect_v4(). Returns 1 if dst_ip is the
 * local node (fib NOT_FWDED), 0 otherwise (delivered / unresolved / error). */
static __always_inline int
pmtu_clone_redirect_v6(struct __ctx_buff *ctx, const union v6addr *dst_ip)
{
	struct bpf_fib_lookup_padded fib = {};
	int ret, oif;

	fib.l.family = AF_INET6;
	ipv6_addr_copy((union v6addr *)&fib.l.ipv6_dst, dst_ip);
	fib.l.ifindex = ctx_get_ifindex(ctx);
	ret = (int)fib_lookup(ctx, &fib.l, sizeof(fib.l), 0);
	if (ret == BPF_FIB_LKUP_RET_NOT_FWDED)
		return 1;		/* destination is the local node */
	if (ret != BPF_FIB_LKUP_RET_SUCCESS && ret != BPF_FIB_LKUP_RET_NO_NEIGH)
		return 0;
	oif = fib.l.ifindex;
	if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
		if (eth_store_daddr(ctx, fib.l.dmac, 0) < 0)
			return 0;
		if (eth_store_saddr(ctx, fib.l.smac, 0) < 0)
			return 0;
	} else {
		/* Route known, neighbor unresolved: resolve via the neigh map. */
		const union macaddr *smac = device_mac(oif);
		const union macaddr *dmac = neigh_lookup_ip6(dst_ip);

		if (!dmac)
			return 0;
		if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
			return 0;
		if (eth_store_saddr_aligned(ctx, smac->addr, 0) < 0)
			return 0;
	}
	clone_redirect(ctx, oif, 0);
	return 0;
}

static long
pmtu_flood_node_cb6(void *map __maybe_unused, const void *key,
		    const void *value, void *arg)
{
	struct pmtu_flood_ctx6 *fc = arg;
	const struct node_key *nk = key;
	const struct node_value *nv = value;
	union v6addr node_ip;
	int ret;

	if (!fc || !nk || !nv)
		return 1;
	if (nk->family != ENDPOINT_KEY_IPV6)
		return 0;		/* IPv6 nodes only */
	if (pmtu_flood_seen(fc->seen, &fc->n_seen, nv->id))
		return 0;		/* already flooded to this node */
	node_ip = nk->ip6;
	if (ipv6_addr_equals(&node_ip, &fc->cur_daddr))
		return 0;

	/* Rewrite the outer destination to this node's IP and amend the ICMPv6
	 * checksum for the address change (pseudo-header). */
	ret = snat_v6_rewrite_headers(fc->ctx, IPPROTO_ICMPV6, ETH_HLEN, true,
				      fc->l4_off, &fc->cur_daddr, &node_ip,
				      IPV6_DADDR_OFF, 0, 0, 0);
	if (ret < 0)
		return 0;
	fc->cur_daddr = node_ip;

	if (pmtu_clone_redirect_v6(fc->ctx, &node_ip)) {
		fc->local_ip = node_ip;	/* deliver original locally after the loop */
		fc->have_local = true;
	}
	return 0;
}

#ifdef HAVE_LOOP		/* bpf_loop: kernel >= 5.17 (see the IPv4 path) */
/* State threaded through the DSR backend flood (bpf_loop callback), IPv6. */
struct pmtu_backend_flood_ctx6 {
	struct __ctx_buff *ctx;
	struct lb6_key key;	/* address = VIP, dport = svc_port; slot mutated */
	union v6addr cur_addr;	/* address currently written (VIP, then last backend) */
	int l4_off;
	__u32 inner_l3_off;
	__u32 icmp_l4_off;
	__be16 cur_port;
	__u8 inner_nexthdr;
	int err;
};

static long
pmtu_flood_backend_cb_v6(__u32 index, void *arg)
{
	struct pmtu_backend_flood_ctx6 *bc = arg;
	const struct lb6_service *be_slot;
	const struct lb6_backend *backend;
	int ret;

	bc->key.backend_slot = (__u16)(index + 1);
	be_slot = __lb6_lookup_backend_slot(&bc->key);
	if (!be_slot || !be_slot->backend_id)
		return 0;
	backend = __lb6_lookup_backend(be_slot->backend_id);
	if (!backend || ipv6_addr_equals(&bc->cur_addr, &backend->address))
		return 0;		/* missing, or already addressed here */

	ret = pmtu_rewrite_to_backend_v6(bc->ctx, bc->inner_nexthdr, bc->inner_l3_off,
					 bc->icmp_l4_off, bc->l4_off, &bc->cur_addr,
					 &backend->address, bc->cur_port,
					 backend->port);
	if (IS_ERR(ret)) {
		bc->err = ret;
		return 1;
	}
	ipv6_addr_copy(&bc->cur_addr, &backend->address);
	bc->cur_port = backend->port;

	pmtu_clone_redirect_v6(bc->ctx, &bc->cur_addr);
	return 0;
}

/* IPv6 non-Maglev DSR backend flood (see pmtu_flood_backends_v4). */
static __always_inline int
pmtu_flood_backends_v6(struct __ctx_buff *ctx, const struct lb6_service *svc,
		       const struct lb6_key *key, int l4_off, __u32 inner_l3_off,
		       __u32 icmp_l4_off, const union v6addr *vip, __be16 svc_port,
		       __u8 inner_nexthdr)
{
	struct pmtu_backend_flood_ctx6 bc = {
		.ctx		= ctx,
		.key		= *key,
		.cur_port	= svc_port,
		.l4_off		= l4_off,
		.inner_l3_off	= inner_l3_off,
		.icmp_l4_off	= icmp_l4_off,
		.inner_nexthdr	= inner_nexthdr,
	};
	__u32 nr = svc->count;

	ipv6_addr_copy(&bc.cur_addr, vip);

	if (nr > PMTU_FLOOD_MAX_BACKENDS)
		nr = PMTU_FLOOD_MAX_BACKENDS;
	loop(nr, pmtu_flood_backend_cb_v6, &bc, 0);
	if (IS_ERR(bc.err))
		return bc.err;

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);
	return DROP_PMTU_RELAYED;
}
#endif /* HAVE_LOOP */
#endif /* !IS_BPF_XDP */

static __always_inline int
handle_icmp_svc_pmtu_v6(struct __ctx_buff *ctx, struct ipv6hdr *ip6, int l4_off,
			__s8 *ext_err __maybe_unused)
{
	__u32 inner_l3_off = (__u32)(l4_off + sizeof(struct icmp6hdr));
	struct ipv6hdr inner;
	struct lb6_key key = {};
	const struct lb6_service *svc;
	const struct lb6_backend *backend;
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	union v6addr vip;
	__be16 svc_port = 0, client_port = 0;
	__u8 inner_nexthdr, type;
	__u32 backend_id, icmp_l4_off;
	int hdrlen, ret;

	if (icmp6_load_type(ctx, l4_off, &type) < 0)
		return DROP_INVALID;
	if (type != ICMPV6_PKT_TOOBIG)
		return CTX_ACT_OK;

	/* Inner packet = the original reply: src = VIP:svc_port, dst = client. */
	if (ctx_load_bytes(ctx, inner_l3_off, &inner, sizeof(inner)) < 0)
		return DROP_INVALID;

	inner_nexthdr = inner.nexthdr;
	hdrlen = ipv6_hdrlen_offset(ctx, (int)inner_l3_off, &inner_nexthdr, NULL);
	if (hdrlen < 0)
		return DROP_INVALID;
	icmp_l4_off = inner_l3_off + (__u32)hdrlen;

	switch (inner_nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;
	default:
		return CTX_ACT_OK;
	}

	if (ctx_load_bytes(ctx, icmp_l4_off, &svc_port, sizeof(svc_port)) < 0)
		return DROP_INVALID;
	if (ctx_load_bytes(ctx, icmp_l4_off + 2, &client_port, sizeof(client_port)) < 0)
		return DROP_INVALID;

	ipv6_addr_copy(&vip, (union v6addr *)&inner.saddr);

	/* Sanity: only handle an error addressed to the VIP that sourced the
	 * dropped packet (outer dst == embedded src). */
	if (!ipv6_addr_equals((union v6addr *)&ip6->daddr, &vip))
		return CTX_ACT_OK;

	ipv6_addr_copy(&key.address, &vip);
	key.dport = svc_port;
	key.proto = inner_nexthdr;

	svc = lb6_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;

	if (pmtu_relay_ratelimited(svc->rev_nat_index))
		return DROP_RATE_LIMITED;

	/* L7/Ingress: flood the error to every node so the node whose cilium-envoy
	 * terminates the connection caches the PMTU (see the IPv4 path). */
	if (lb6_svc_is_l7_loadbalancer(svc)) {
#ifndef IS_BPF_XDP
		struct pmtu_flood_ctx6 fc = {};
		struct pmtu_flood_scratch *scratch;
		__u32 zero = 0;

		/* Borrow the per-CPU dedup scratch (see the IPv4 path). The struct
		 * has no large array now, so a plain aggregate initialiser zeroes
		 * it with correctly-aligned compiler stores. */
		scratch = map_lookup_elem(&cilium_pmtu_flood_scratch, &zero);
		if (!scratch)
			return CTX_ACT_OK;
		fc.ctx = ctx;
		fc.seen = scratch->seen;
		fc.l4_off = l4_off;
		ipv6_addr_copy(&fc.cur_daddr, &vip);	/* current outer daddr */
		/* have_local, n_seen and local_ip are left zero by the initialiser. */

		for_each_map_elem(&cilium_node_map_v2, pmtu_flood_node_cb6, &fc, 0);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

		if (fc.have_local) {
			/* Deliver the original to the local host stack. */
			ret = snat_v6_rewrite_headers(ctx, IPPROTO_ICMPV6, ETH_HLEN,
						      true, l4_off, &fc.cur_daddr,
						      &fc.local_ip, IPV6_DADDR_OFF,
						      0, 0, 0);
			if (IS_ERR(ret))
				return ret;
			return CTX_ACT_OK;
		}
		return DROP_PMTU_RELAYED;
#else
		return CTX_ACT_OK;
#endif
	}

	/* Rewriting the embedded packet keeps the outer ICMPv6 checksum valid only
	 * because the embedded address change and the embedded L4 checksum change
	 * cancel (IPv6 has no L3 checksum). A UDP reply with checksum 0 ("no
	 * checksum") has no L4 checksum to cancel the address/port change, so the
	 * rewrite would leave the outer ICMPv6 checksum wrong and the backend would
	 * drop the relayed error. Don't emit a malformed error for that rare case;
	 * fall through to the previous behavior. (The stock
	 * snat_v6_rev_nat_handle_icmp_pkt_toobig() shares this limitation; fully
	 * supporting it needs an outer-checksum diff in the shared helper.) */
	if (inner_nexthdr == IPPROTO_UDP) {
		__be16 l4_csum = 0;

		if (ctx_load_bytes(ctx, (int)(icmp_l4_off + offsetof(struct udphdr, check)),
				   &l4_csum, sizeof(l4_csum)) < 0)
			return DROP_INVALID;
		if (l4_csum == 0)
			return CTX_ACT_OK;
	}

	/* Build the flow tuple once; both paths key on it (see the IPv4 path for
	 * the handedness rationale). */
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&inner.daddr);	/* client */
	ipv6_addr_copy(&tuple.daddr, &vip);				/* VIP */
	tuple.nexthdr = inner_nexthdr;
	tuple.sport = svc_port;
	tuple.dport = client_port;

	if (svc->flags2 & SVC_FLAG_FWD_MODE_DSR) {
		/* DSR: re-derive the backend statelessly under Maglev; under any
		 * other algorithm flood the error to every backend instead (see the
		 * IPv4 path). Resolve the effective algorithm the same way
		 * lb6_select_backend_id() does. */
		__u32 alg = lb6_algorithm(svc);

		if (alg != LB_SELECTION_MAGLEV && alg != LB_SELECTION_RANDOM &&
		    alg != LB_SELECTION_FIRST)
			alg = lb_default_algorithm();
		if (alg != LB_SELECTION_MAGLEV) {
#if !defined(IS_BPF_XDP) && defined(HAVE_LOOP)
			return pmtu_flood_backends_v6(ctx, svc, &key, l4_off,
						      inner_l3_off, icmp_l4_off,
						      &vip, svc_port, inner_nexthdr);
#else
			/* flood is TC-only and needs bpf_loop (HAVE_LOOP) */
			return CTX_ACT_OK;
#endif
		}
		backend_id = lb6_select_backend_id(ctx, &key, &tuple, svc);
	} else {
		/* SNAT-mode: best-effort recovery from the service conntrack entry,
		 * which only exists on the ingress node (see the IPv4 path). */
		struct ct_state ct_state = { .rev_nat_index = svc->rev_nat_index };
		__u32 monitor = 0;

		ret = ct_lazy_lookup6(get_ct_map6(&tuple), &tuple, ctx,
				      IPFRAG_BIT_NO_L4_HEADER, (int)icmp_l4_off,
				      CT_SERVICE, SCOPE_REVERSE, CT_ENTRY_SVC,
				      &ct_state, &monitor);
		if (ret != CT_REPLY)
			return CTX_ACT_OK;	/* no local CT entry: not the ingress node */
		backend_id = ct_state.backend_id;
	}

	if (!backend_id)
		return CTX_ACT_OK;
	backend = __lb6_lookup_backend(backend_id);
	if (!backend)
		return CTX_ACT_OK;

	/* Re-address the error to the backend (embedded src + outer dst), see
	 * pmtu_rewrite_to_backend_v6(). */
	ret = pmtu_rewrite_to_backend_v6(ctx, inner_nexthdr, inner_l3_off,
					 icmp_l4_off, l4_off, &vip, &backend->address,
					 svc_port, backend->port);
	if (IS_ERR(ret))
		return ret;

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

	return CTX_ACT_REDIRECT;
}

#endif /* ENABLE_IPV6 */

#endif /* ENABLE_SVC_ICMP_PMTU_RELAY */
