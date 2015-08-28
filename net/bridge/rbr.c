/*
 *	Generic parts
 *	Linux ethernet Rbridge
 *
 *	Authors:
 *	Ahmed AMAMOU	<ahmed@gandi.net>
 *	Kamel Haddadou	<kamel@gandi.net>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
#include "br_private.h"
#include "rbr_private.h"
#include <linux/netfilter_bridge.h>
#include <net/if_trill.h>

static void rbr_del_all(struct rbr *rbr);

static struct rbr *add_rbr(struct net_bridge *br)
{
	struct rbr *rbr;

	if (!br->rbr) {
		rbr = kzalloc(sizeof(*rbr), GFP_KERNEL);
		if (!rbr)
			return NULL;

		rbr->br = br;
		rbr->nick = RBRIDGE_NICKNAME_NONE;
		rbr->treeroot = RBRIDGE_NICKNAME_NONE;
		return rbr;
	}

	return br->rbr;
}

static void br_trill_start(struct net_bridge *br)
{
	struct net_bridge_port *p;
	/* Disable STP if it is already enabled */

	if (br->stp_enabled != BR_NO_STP)
		br_stp_set_enabled(br, false);
	br->rbr = add_rbr(br);
	if (br->rbr) {
		list_for_each_entry(p, &br->port_list, list) {
			struct net_device *dev = p->dev;

			rcu_assign_pointer(dev->rx_handler, rbr_handle_frame);
		}
		br->trill_enabled = BR_TRILL;
		return;
	}
	pr_warn("RBridge allocation for bridge '%s' failed\n", br->dev->name);
}

static void br_trill_stop(struct net_bridge *br)
{
	struct rbr *old;
	struct net_bridge_port *p;

	spin_lock_bh(&br->lock);
	br->trill_enabled = BR_NO_TRILL;
	spin_unlock_bh(&br->lock);
	old = br->rbr;
	br->rbr = NULL;
	if (likely(old)) {
		list_for_each_entry(p, &br->port_list, list) {
			struct net_device *dev = p->dev;

			rcu_assign_pointer(dev->rx_handler, br_handle_frame);
		}
		rbr_del_all(old);
		kfree(old);
	}
}

void br_trill_set_enabled(struct net_bridge *br, unsigned long val)
{
	if (val) {
		if (br->trill_enabled == BR_NO_TRILL)
			br_trill_start(br);
	} else {
		if (br->trill_enabled != BR_NO_TRILL)
			br_trill_stop(br);
	}
}

int set_treeroot(struct rbr *rbr, uint16_t treeroot)
{
	if (unlikely(!VALID_NICK(treeroot))) {
		pr_warn_ratelimited
			("rbr_set_treeroot: given tree root not valid\n");
		return -ENOENT;
	}
	if (rbr->treeroot != treeroot)
		rbr->treeroot = treeroot;
	return 0;
}

struct rbr_node *rbr_find_node(struct rbr *rbr, __u16 nickname)
{
	struct rbr_node *rbr_node;

	if (unlikely(!VALID_NICK(nickname)))
		return NULL;
	rbr_node = rcu_dereference(rbr->rbr_nodes[nickname]);
	rbr_node_get(rbr_node);

	return rbr_node;
}

static void rbr_del_node(struct rbr *rbr, uint16_t nickname)
{
	struct rbr_node *rbr_node;

	if (likely(VALID_NICK(nickname))) {
		rbr_node = rbr->rbr_nodes[nickname];
		if (likely(rbr_node)) {
			rcu_assign_pointer(rbr->rbr_nodes[nickname], NULL);
			rbr_node_put(rbr_node);
		}
	}
}

static void rbr_del_all(struct rbr *rbr)
{
	unsigned int i;

	for (i = RBRIDGE_NICKNAME_MIN; i < RBRIDGE_NICKNAME_MAX; i++) {
		if (likely(rbr->rbr_nodes[i]))
			rbr_del_node(rbr, i);
	}
}

static bool add_header(struct sk_buff *skb, uint16_t ingressnick,
		       u16 egressnick, bool multidest)
{
	struct trill_hdr *trh;
	size_t trhsize;
	u16 vlan_tci;
	u16 trill_flags = 0;
#ifdef CONFIG_TRILL_VNT
	struct trill_opt *trill_opt;
	struct trill_vnt_extension *vnt;
	struct net_bridge_port *p;
	u32 vni = 0;
	u16 vnt_flags = 0;
	u32 opt_flows = 0;
	u32 opt_flags = 0;
#endif

	trhsize = sizeof(*trh);
#ifdef CONFIG_TRILL_VNT
	p = br_port_get_rcu(skb->dev);
	if (p)
		vni = get_port_vni_id(p);
	if (vni)
		trhsize += sizeof(struct trill_opt) +
			   sizeof(struct trill_vnt_extension);
#endif

	skb_push(skb, ETH_HLEN);
	if (!skb->encapsulation) {
		skb_reset_inner_headers(skb);
		skb->encapsulation = 1;
	}
	/* fix inner VLAN */
	if (br_vlan_get_tag(skb, &vlan_tci) == 0) {
		skb = vlan_insert_tag(skb, skb->vlan_proto, vlan_tci);
		if (!skb) {
			pr_err("add_header: vlan_insert_tag failed\n");
			return 1;
		}
		skb->vlan_proto = 0;
		skb->vlan_tci = 0;
	}
	if (unlikely(skb_cow_head(skb, trhsize + ETH_HLEN))) {
		pr_err("add_header: cow_head failed\n");
		return 1;
	}
#ifdef CONFIG_TRILL_VNT
	if (vni) {
		vnt = (struct trill_vnt_extension *)skb_push(skb,
							     sizeof(*vnt));
		trill_opt = (struct trill_opt *)skb_push(skb,
							 sizeof(*trill_opt));
		/* opt_flags to be defined later */
		trill_opt->opt_flag = htonl(opt_flags);
		/* opt_flows will be used for multipath */
		trill_opt->opt_flow = htonl(opt_flows);
		vnt_flags = vnt_flags |
			trill_extension_set_app(0) |
			trill_extension_set_nc(0) |
			trill_extension_set_type(VNT_EXTENSION_TYPE) |
			trill_extension_set_mu(0) |
			trill_extension_set_length(VNT_EXTENSION_LENGTH);
		vnt->flags = htons(vnt_flags);
		vnt->reserved_high = htons(0);
		trill_extension_set_vni(vnt, vni_to_network(vni));
		trill_flags = trill_set_optslen(trill_flags,
						sizeof(*trill_opt) +
						sizeof(*vnt)
						);
	}
#endif

	trh = (struct trill_hdr *)skb_push(skb, sizeof(*trh));
	trill_flags = trill_set_version(trill_flags, TRILL_PROTOCOL_VERS);
	trill_flags = trill_set_hopcount(trill_flags, TRILL_DEFAULT_HOPS);
	trill_flags = trill_set_multidest(trill_flags, multidest ? 1 : 0);

	trh->th_flags = htons(trill_flags);
	trh->th_egressnick = egressnick;
	trh->th_ingressnick = ingressnick;	/* self nick name */
	/* make skb->mac_header point to outer mac header */
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);	/* instead of the inner one */
	eth_hdr(skb)->h_proto = htons(ETH_P_TRILL);
	/* reset skb->data pointer */
	skb_pull(skb, ETH_HLEN);
	skb_reset_mac_len(skb);
	return 0;
}

static void rbr_fwd(struct net_bridge_port *p, struct sk_buff *skb,
		    u16 adj_nick, u16 vid)
{
	struct rbr_node *adj;
	struct trill_hdr *trh;
	struct ethhdr *outerethhdr;
	struct net *net = dev_net(p->dev);
	struct net_device *outdev;
	struct net_bridge_port *outp;

	adj = rbr_find_node(p->br->rbr, adj_nick);
	if (unlikely(!adj || !adj->rbr_ni)) {
		pr_warn_ratelimited("rbr_fwd: unable to find adjacent RBridge\n");
		goto dest_fwd_fail;
	}
	outdev = dev_get_by_index_rcu(net, adj->rbr_ni->linkid);
	if (!outdev) {
		pr_warn_ratelimited("rbr_fwd: cannot find source port device for forwrding\n");
		goto dest_fwd_fail;
	}

	trh = (struct trill_hdr *)skb->data;
	trillhdr_dec_hopcount(trh);
	outerethhdr = eth_hdr(skb);

	/* change outer ether header */
	/* bridge becomes the source_port address in outeretherhdr */
	outp = br_port_get_rcu(outdev);
	ether_addr_copy(outerethhdr->h_source, outp->dev->dev_addr);
	/* dist port becomes dest address in outeretherhdr */
	ether_addr_copy(outerethhdr->h_dest, adj->rbr_ni->adjsnpa);
	rbr_node_put(adj);
	skb->dev = p->br->dev;
	br_forward(outp, skb, NULL);
	return;

dest_fwd_fail:
	if (likely(p && p->br))
		p->br->dev->stats.tx_dropped++;
	kfree_skb(skb);
}

static int rbr_multidest_fwd(struct net_bridge_port *p,
			     struct sk_buff *skb, u16 egressnick,
			     u16 ingressnick, const u8 *saddr,
			     u16 vid, bool free)
{
	struct rbr *rbr;
	struct rbr_node *dest;
	struct rbr_node *adj;
	struct sk_buff *skb2;
	u16 adjnicksaved = 0;
	u16 adjnick;
	bool nicksaved = false;
	unsigned int i;

	if (unlikely(!p)) {
		pr_warn_ratelimited("rbr_multidest_fwd: port error\n");
		goto multidest_fwd_fail;
	}

	rbr = p->br->rbr;
	if (unlikely(!rbr))
		goto multidest_fwd_fail;

	/* Lookup the egress nick info, this is the DT root */
	dest = rbr_find_node(rbr, egressnick);
	if (!dest) {
		pr_warn_ratelimited
		    ("rbr_multidest_fwd: unable to find egress\n");
		goto multidest_fwd_fail;
	}

	/* Send a copy to all our adjacencies on the DT root */
	for (i = 0; i < dest->rbr_ni->adjcount; i++) {
		/* Check for a valid adjacency node */
		adjnick = RBR_NI_ADJNICK(dest->rbr_ni, i);
		adj = rbr_find_node(rbr, adjnick);
		if (!VALID_NICK(adjnick) || ingressnick == adjnick ||
		    (!adj))
			continue;
		/* Do not forward back to adjacency that sent the pkt to us */
		if ((saddr) &&
		    (ether_addr_equal_unaligned(adj->rbr_ni->adjsnpa,
						saddr))) {
			rbr_node_put(adj);
			continue;
		}

		/* save the first found adjacency to avoid coping SKB
		 * if no other adjacency is found later no frame copy
		 * will be made if other adjacency will be found frame
		 * will be copied and forwarded to them if skb is needed
		 * after rbr_multidest_fwd copy of the first skb skb
		 * will be forced
		 */
		if (!nicksaved && free) {
			adjnicksaved = adjnick;
			nicksaved = true;
			rbr_node_put(adj);
			continue;
		}
		/* FIXME using copy instead of clone as
		 * we are going to modify dest address
		 */
		skb2 = skb_copy(skb, GFP_ATOMIC);
		if (unlikely(!skb2)) {
			p->br->dev->stats.tx_dropped++;
			pr_warn_ratelimited
			    ("rbr_multidest_fwd: skb_copy failed\n");
			goto multidest_fwd_fail;
		}
		rbr_fwd(p, skb2, adjnick, vid);
		rbr_node_put(adj);
	}
	rbr_node_put(dest);

	/* if nicksave is false it means that copy will not be forwarded
	 * as no availeble ajacency was found in such a case frame should
	 * be dropped
	 */

	if (nicksaved)
		rbr_fwd(p, skb, adjnicksaved, vid);
	else
		kfree_skb(skb);

	return 0;

 multidest_fwd_fail:
	if (likely(p && p->br))
		p->br->dev->stats.tx_dropped++;
	kfree_skb(skb);
	return -EINVAL;
}

static void rbr_encaps(struct sk_buff *skb, u16 egressnick, u16 vid)
{
	u16 local_nick;
	u16 dtnick;
	struct rbr_node *self;
	struct sk_buff *skb2;
	struct rbr *rbr;
	struct net_bridge_port *p;
#ifdef CONFIG_TRILL_VNT
	struct vni *vni;
	u32 vni_id;
#endif

	p = br_port_get_rcu(skb->dev);
	if (unlikely(!p)) {
		pr_warn_ratelimited("rbr_encaps_prepare: port error\n");
		goto encaps_drop;
	}
	rbr = p->br->rbr;

	if (unlikely(egressnick != RBRIDGE_NICKNAME_NONE &&
		     !VALID_NICK(egressnick))) {
		pr_warn_ratelimited
		    ("rbr_encaps_prepare: invalid destinaton nickname\n");
		goto encaps_drop;
	}
	local_nick = rbr->nick;
	if (unlikely(!VALID_NICK(local_nick))) {
		pr_warn_ratelimited
		    ("rbr_encaps_prepare: invalid local nickname\n");
		goto encaps_drop;
	}
	/* Daemon has not yet sent the local nickname */
	self = rbr_find_node(rbr, local_nick);
	if (unlikely(!self)) {
		pr_warn_ratelimited
		    ("rbr_encaps_prepare: waiting for nickname\n");
		goto encaps_drop;
	}

	/* Unknown destination => multidestination frame */
	if (egressnick == RBRIDGE_NICKNAME_NONE) {
		if (self->rbr_ni->dtrootcount > 0)
			dtnick = RBR_NI_DTROOTNICK(self->rbr_ni, 0);
		else
			dtnick = rbr->treeroot;
		rbr_node_put(self);
		if (unlikely(!VALID_NICK(dtnick))) {
			pr_warn_ratelimited
			    ("rbr_encaps_prepare: dtnick is unvalid\n");
			goto encaps_drop;
		}
		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (unlikely(!skb2)) {
			p->br->dev->stats.tx_dropped++;
			pr_warn_ratelimited
			    ("rbr_encaps_prepare: skb_clone failed\n");
			goto encaps_drop;
		}
#ifdef CONFIG_TRILL_VNT
		vni_id = get_port_vni_id(p);
		if (vni_id) {
			vni = find_vni(p->br, vni_id);
			vni_flood_deliver(vni, skb2, FREE_SKB);
		} else
#endif
		br_flood_deliver_flags(p->br, skb2, true, TRILL_FLAG_ACCESS);
		if (unlikely(add_header(skb, local_nick, dtnick, 1)))
			goto encaps_drop;
		rbr_multidest_fwd(p, skb, dtnick, local_nick, NULL, vid, true);
	} else {
		if (unlikely(add_header(skb, local_nick, egressnick, 0)))
			goto encaps_drop;
		rbr_fwd(p, skb, egressnick, vid);
	}
	return;
 encaps_drop:
	if (likely(p && p->br))
		p->br->dev->stats.tx_dropped++;
	kfree_skb(skb);
}

#ifdef CONFIG_TRILL_VNT
static void rbr_decap_finish(struct sk_buff *skb, u16 vid,
			     uint32_t vni)
#else
static void rbr_decap_finish(struct sk_buff *skb, u16 vid)
#endif
{
	struct net_bridge *br;
	struct net_bridge_port *p;
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_fdb_entry *dst;

	p = br_port_get_rcu(skb->dev);
	br = p->br;
	dst = __br_fdb_get(br, dest, vid);
	if (dst) {
	#ifdef CONFIG_TRILL_VNT
		if (get_port_vni_id(dst->dst) != vni)
			goto rbr_decap_finish_drop;
		else
	#endif
			br_deliver(dst->dst, skb);
	} else {
		#ifdef CONFIG_TRILL_VNT
		if (vni) {
			struct vni *VNI;

			VNI = find_vni(br, vni);
			if (VNI)
				vni_flood_deliver(VNI, skb, FREE_SKB);
			else
				goto rbr_decap_finish_drop;
		} else
		#endif
			do {
				br_flood_deliver_flags(p->br, skb, true,
						       TRILL_FLAG_ACCESS
						      );
			} while (0);
	}
	return;
rbr_decap_finish_drop:
	kfree_skb(skb);
}

static void rbr_decaps(struct net_bridge_port *p,
		       struct sk_buff *skb, size_t trhsize, u16 vid)
{
	struct trill_hdr *trh;
	struct ethhdr *hdr;
#ifdef CONFIG_TRILL_VNT
	u32 vni = 0;
#endif

	if (unlikely(!p))
		goto rbr_decaps_drop;
	trh = (struct trill_hdr *)skb->data;
	if (trhsize >= sizeof(*trh))
		skb_pull(skb, sizeof(*trh));
	else
		goto rbr_decaps_drop;
	trhsize -= sizeof(*trh);
#ifdef CONFIG_TRILL_VNT
	if (trill_get_optslen(ntohs(trh->th_flags))) {
		struct trill_vnt_extension *vnt;

		if (trhsize > sizeof(struct trill_opt))
			skb_pull(skb, sizeof(struct trill_opt));
		else
			goto rbr_decaps_drop;
		trhsize -= sizeof(struct trill_opt);
		vnt = (struct trill_vnt_extension *)skb->data;
		if (trill_extension_get_type(vnt->flags !=
					     VNT_EXTENSION_TYPE)) {
			kfree_skb(skb);
			return;
		}
		vni = network_to_vni((uint32_t)trill_extension_get_vni(vnt));
		if (trhsize >= sizeof(*vnt))
			skb_pull(skb, sizeof(*vnt));
		else
			goto rbr_decaps_drop;
		trhsize -= sizeof(*vnt);
		if (trhsize > 0) {
			pr_warn_ratelimited("unknown option encountred dropping frame for safety\n");
			goto rbr_decaps_drop;
		}
	}
#endif

	skb_reset_mac_header(skb);	/* instead of the inner one */
	skb->protocol = eth_hdr(skb)->h_proto;
	hdr = (struct ethhdr *)skb->data;
	skb_pull(skb, ETH_HLEN);
	skb_reset_network_header(skb);
	if (skb->encapsulation)
		skb->encapsulation = 0;
	br_fdb_update_nick(p->br, p, hdr->h_source, vid, false,
			   trh->th_ingressnick);
#ifdef CONFIG_TRILL_VNT
	rbr_decap_finish(skb, vid, vni);
#else
	rbr_decap_finish(skb, vid);
#endif
	return;
 rbr_decaps_drop:
	if (likely(p && p->br))
		p->br->dev->stats.rx_dropped++;
	kfree_skb(skb);
}

static void rbr_recv(struct sk_buff *skb, u16 vid)
{
	u16 local_nick, dtnick, adjnick, idx;
	struct rbr *rbr;
	struct trill_hdr *trh;
	size_t trhsize;
	struct net_bridge_port *p;
	u16 trill_flags;
	struct sk_buff *skb2;
	struct rbr_node *dest = NULL;
	struct rbr_node *source_node = NULL;
	struct rbr_node *adj = NULL;

	p = br_port_get_rcu(skb->dev);
	if (unlikely(!p)) {
		pr_warn_ratelimited("rbr_recv: port error\n");
		goto recv_drop;
	}
	rbr = p->br->rbr;
	/* For trill frame the outer mac destination must correspond
	 * to localhost address, if not frame must be discarded
	 * such scenario is possible when switch flood frames on all ports
	 * if frame are not discarded they will loop until reaching the
	 * hop_count limit
	 */
	if (memcmp(p->dev->dev_addr, eth_hdr(skb)->h_dest, ETH_ALEN))
		goto recv_drop;
	trh = (struct trill_hdr *)skb->data;
	trill_flags = ntohs(trh->th_flags);
	trhsize = sizeof(*trh) + trill_get_optslen(trill_flags);
	if (unlikely(skb->len < trhsize + ETH_HLEN)) {
		pr_warn_ratelimited
		    ("rbr_recv: sk_buff len is less then minimal len\n");
		goto recv_drop;
	}
	/* seems to be a valid TRILL frame,
	 * check if TRILL header can be pulled
	 * before proceeding
	 */
	if (unlikely(!pskb_may_pull(skb, trhsize + ETH_HLEN)))
		goto recv_drop;

	/* WARNING SKB structure may be changed by pskb_may_pull
	 * reassign trh pointer before continuing any further
	 */
	trh = (struct trill_hdr *)skb->data;

	if (!skb->encapsulation) {
		skb_pull(skb, trhsize + ETH_HLEN);
		skb_reset_inner_headers(skb);
		skb->encapsulation = 1;
		skb_push(skb, trhsize + ETH_HLEN);
	}
	if (unlikely(!VALID_NICK(trh->th_ingressnick) ||
		     !VALID_NICK(trh->th_egressnick))) {
		pr_warn_ratelimited("rbr_recv: invalid nickname\n");
		goto recv_drop;
	}
	if (unlikely(trill_get_version(trill_flags) != TRILL_PROTOCOL_VERS)) {
		pr_warn_ratelimited("rbr_recv: not the same trill version\n");
		goto recv_drop;
	}
	local_nick = rbr->nick;
	dtnick = rbr->treeroot;
	if (unlikely(trh->th_ingressnick == local_nick)) {
		pr_warn_ratelimited
		    ("rbr_recv:looping back frame check your config\n");
		goto recv_drop;
	}

	if (!trill_get_multidest(trill_flags)) {
		/* ntohs not needed as the 2 are in the same bit form */
		if (trh->th_egressnick == trh->th_ingressnick) {
			pr_warn_ratelimited
			    ("rbr_recv: egressnick == ingressnick\n");
			goto recv_drop;
		}
		if (trh->th_egressnick == local_nick) {
			rbr_decaps(p, skb, trhsize, vid);
		} else if (likely(trill_get_hopcount(trill_flags))) {
			br_fdb_update(p->br, p, eth_hdr(skb)->h_source,
				      vid, false);
			rbr_fwd(p, skb, trh->th_egressnick, vid);
		} else {
			pr_warn_ratelimited("rbr_recv: hop count limit reached\n");
			goto recv_drop;
		}
		return;
	}

	/* Multi-destination frame:
	 * Check if received multi-destination frame from an
	 * adjacency in the distribution tree rooted at egress nick
	 * indicated in the frame header
	 */
	dest = rbr_find_node(rbr, trh->th_egressnick);
	if (unlikely(!dest)) {
		pr_warn_ratelimited
		    ("rbr_recv: mulicast  with unknown destination\n");
		goto recv_drop;
	}
	for (idx = 0; idx < dest->rbr_ni->adjcount; idx++) {
		adjnick = RBR_NI_ADJNICK(dest->rbr_ni, idx);
		adj = rbr_find_node(rbr, adjnick);
		if (unlikely(!adj || !adj->rbr_ni))
			continue;
		if (memcmp(adj->rbr_ni->adjsnpa, eth_hdr(skb)->h_source,
			   ETH_ALEN) == 0) {
			rbr_node_put(adj);
			break;
		}
		rbr_node_put(adj);
	}

	if (unlikely(idx >= dest->rbr_ni->adjcount)) {
		pr_warn_ratelimited("rbr_recv: multicast unknown mac source\n");
		rbr_node_put(dest);
		goto recv_drop;
	}

	/* Reverse path forwarding check.
	 * Check if the ingress RBridge  that has forwarded
	 * the frame advertised the use of the distribution tree specified
	 * in the egress nick
	 */
	source_node = rbr_find_node(rbr, trh->th_ingressnick);
	if (unlikely(!source_node)) {
		pr_warn_ratelimited
		    ("rbr_recv: reverse path forwarding check failed\n");
		rbr_node_put(dest);
		goto recv_drop;
	}
	for (idx = 0; idx < source_node->rbr_ni->dtrootcount; idx++) {
		if (RBR_NI_DTROOTNICK(source_node->rbr_ni, idx) ==
		    trh->th_egressnick)
			break;
	}

	if (idx >= source_node->rbr_ni->dtrootcount) {
		/* Allow receipt of forwarded frame with the highest
		 * tree root RBridge as the egress RBridge when the
		 * ingress RBridge has not advertised the use of any
		 * distribution trees.
		 */
		if (source_node->rbr_ni->dtrootcount != 0 ||
		    trh->th_egressnick != dtnick) {
			rbr_node_put(source_node);
			rbr_node_put(dest);
			goto recv_drop;
		}
	}

	/* Check hop count before doing any forwarding */
	if (unlikely(trill_get_hopcount(trill_flags) == 0)) {
		pr_warn_ratelimited
		    ("rbr_recv: multicast hop count limit reached\n");
		rbr_node_put(dest);
		goto recv_drop;
	}
	/* Forward frame using the distribution tree specified by egress nick */
	rbr_node_put(source_node);
	rbr_node_put(dest);

	/* skb2 will be multi forwarded and skb will be locally decaps */
	skb2 = skb_clone(skb, GFP_ATOMIC);
	if (unlikely(!skb2)) {
		p->br->dev->stats.tx_dropped++;
		pr_warn_ratelimited("rbr_recv: multicast skb_clone failed\n");
		goto recv_drop;
	}

	if (rbr_multidest_fwd(p, skb2, trh->th_egressnick, trh->th_ingressnick,
			      eth_hdr(skb)->h_source, vid, false))
		goto recv_drop;

	/* Send de-capsulated frame locally */
	rbr_decaps(p, skb, trhsize, vid);

	return;
 recv_drop:
	if (likely(p && p->br))
		p->br->dev->stats.rx_dropped++;
	kfree_skb(skb);
}

/* handling function hook allow handling
 * a frame upon reception called via
 * br_handle_frame_hook = rbr_handle_frame
 * in  br.c
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock
 */
rx_handler_result_t rbr_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge *br;
	struct net_bridge_port *p;
	struct sk_buff *skb = *pskb;
	u16 vid = 0;
	u16 nick;

	p = br_port_get_rcu(skb->dev);
	br = p->br;
	if (!br || !br->rbr)
		goto drop_no_stat;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;
	if (unlikely(!is_valid_ether_addr(eth_hdr(skb)->h_source))) {
		pr_warn_ratelimited("rbr_handle_frame: invalid src address\n");
		goto drop;
	}
	if (!br_allowed_ingress(p->br, nbp_get_vlan_info(p), skb, &vid))
		goto drop;
	/* do not handle any BPDU from the moment */
	if (is_all_rbr_address((const u8 *)&eth_hdr(skb)->h_dest)) {
		br_fdb_update(br, p, eth_hdr(skb)->h_source, vid, false);
		/* BPDU has to be dropped */
		goto drop_no_stat;
	}
	/* DROP if port is in disable state */
	if (p->trill_flag & TRILL_FLAG_DISABLE)
		goto drop;
	/* ACCESS port encapsulate packets */
	if (p->trill_flag & TRILL_FLAG_ACCESS) {
		/* check if destination is connected on the same bridge */
		struct net_bridge_fdb_entry *dst;

		dst = __br_fdb_get(br, eth_hdr(skb)->h_dest, vid);
		if (likely(dst)) {
			if (dst->dst->trill_flag & TRILL_FLAG_ACCESS) {
				# ifdef CONFIG_TRILL_VNT
				if (get_port_vni_id(p) !=
				    get_port_vni_id(dst->dst))
					goto drop;
				else
				#endif
				br_deliver(dst->dst, skb);
				return RX_HANDLER_CONSUMED;
			}
		}

		/* if packet is from access port and trill is enabled and dest
		 * is not an access port or is unknown, encaps it
		 */
		nick = get_nick_from_mac(p, eth_hdr(skb)->h_dest, vid);
		rbr_encaps(skb, nick, vid);
		return RX_HANDLER_CONSUMED;
	}
	if (p->trill_flag & TRILL_FLAG_TRUNK) {
		/* packet is from trunk port and trill is enabled */
		if (eth_hdr(skb)->h_proto == htons(ETH_P_TRILL)) {
			/* Packet is from trunk port, decapsulate
			 * if destined to access port
			 * or trill forward to next hop
			 */
			rbr_recv(skb, vid);
			return RX_HANDLER_CONSUMED;
		}
		/* packet is destinated to localhost */
		if (ether_addr_equal(p->br->dev->dev_addr,
				     eth_hdr(skb)->h_dest)) {
			skb->pkt_type = PACKET_HOST;
			NF_HOOK(NFPROTO_BRIDGE, NF_BR_PRE_ROUTING, NULL, skb,
				skb->dev, NULL,
				br_handle_frame_finish);
			return RX_HANDLER_CONSUMED;
		}

		/* packet is not from trill  we don't handle
		 * such packet from the moment
		 */
	}

 drop:
	if (br->dev)
		br->dev->stats.rx_dropped++;
 drop_no_stat:
	kfree_skb(skb);
	return RX_HANDLER_CONSUMED;
}
