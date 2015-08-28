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
	/* Disable STP if it is already enabled */

	if (br->stp_enabled != BR_NO_STP)
		br_stp_set_enabled(br, false);
	br->rbr = add_rbr(br);
	if (br->rbr)
		br->trill_enabled = BR_TRILL;
	else
		pr_warn("RBridge allocation for bridge '%s' failed\n",
			br->dev->name);
}

static void br_trill_stop(struct net_bridge *br)
{
	struct rbr *old;

	spin_lock_bh(&br->lock);
	br->trill_enabled = BR_NO_TRILL;
	spin_unlock_bh(&br->lock);
	old = br->rbr;
	br->rbr = NULL;
	if (likely(old)) {
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

	trhsize = sizeof(*trh);
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

static void rbr_encaps(struct sk_buff *skb, u16 egressnick, u16 vid)
{
	u16 local_nick;
	u16 dtnick;
	struct rbr_node *self;
	struct sk_buff *skb2;
	struct rbr *rbr;
	struct net_bridge_port *p;

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
		br_flood_deliver_flags(p->br, skb2, true, TRILL_FLAG_ACCESS);
		if (unlikely(add_header(skb, local_nick, dtnick, 1)))
			goto encaps_drop;
		/* TODO Multi forward */
	} else {
		if (unlikely(add_header(skb, local_nick, egressnick, 0)))
			goto encaps_drop;
		/* TODO simple forwarding */
	}
	return;
 encaps_drop:
	if (likely(p && p->br))
		p->br->dev->stats.tx_dropped++;
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
			/* TODO */
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
