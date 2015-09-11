/*
 *	Generic parts
 *	Linux ethernet Rbridge
 *
 *	Authors:
 *	Ahmed AMAMOU	<ahmed@gandi.net>
 *	William Dauchy	<william@gandi.net>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <net/rtnetlink.h>
#include "br_private.h"
#include "rbr_private.h"

int rbr_set_data(struct net_device *dev, struct nlattr *tb[],
		 struct nlattr *data[])
{
	struct net_bridge *br = netdev_priv(dev);
	u16 nick;
	int err = -ENOMEM;

	if (!br)
		return -EINVAL;

	if (data[IFLA_TRILL_NICKNAME]) {
		nick = nla_get_u16(data[IFLA_TRILL_NICKNAME]);
		if (br->trill_enabled == BR_NO_TRILL)
			br_trill_set_enabled(br, 1);

		spin_lock_bh(&br->lock);
		if (VALID_NICK(nick))
			br->rbr->nick = htons(nick);
		spin_unlock_bh(&br->lock);
#ifdef CONFIG_TRILL_VNT
		rbr_notify_vni(br);
#endif
	}
	if (data[IFLA_TRILL_ROOT]) {
		if (!br->rbr)
			return -EINVAL;
		nick = nla_get_u16(data[IFLA_TRILL_ROOT]);
		err = set_treeroot(br->rbr, htons(nick));
	}
	if (data[IFLA_TRILL_INFO]) {
		struct rbr_nickinfo *rbr_ni;
		struct rbr_node *old;
		size_t old_size = 0;
		size_t size = 0;
		struct rbr *rbr;

		if (!br->rbr)
			return -EINVAL;

		rbr = br->rbr;
		size = nla_len(data[IFLA_TRILL_INFO]);
		rbr_ni = kzalloc(size, GFP_KERNEL);
		if (!rbr_ni)
			goto fail;
		memcpy(rbr_ni, nla_data(data[IFLA_TRILL_INFO]), size);
		nick = rbr_ni->nick;
		old = rbr->rbr_nodes[nick];
		if (old) {
			old_size = RBR_NI_TOTALSIZE(old->rbr_ni);
			/* we wait the second topology compute */
			if (unlikely(!br->trill_ready))
				br->trill_ready = true;
		}
		/* replace old node by a new one only if nickname
		 * information have changed
		 */
		if (!old || old_size != size ||
		    memcmp(old->rbr_ni, rbr_ni, size)) {
			struct rbr_node *new;

			new = kzalloc(sizeof(*old), GFP_KERNEL);
			if (!new) {
				kfree(rbr_ni);
				goto fail;
			}
			atomic_set(&new->refs, 1);
			new->rbr_ni = rbr_ni;
			/* Avoid deleting node while it is been used for
			 * routing
			 */
			rcu_assign_pointer(rbr->rbr_nodes[nick], new);
			if (old)
				rbr_node_put(old);
		} else {
			kfree(rbr_ni);
		}
	}
	return 0;
fail:
	pr_warn("rbr_set_data FAILED\n");
	return err;
}

#ifdef CONFIG_TRILL_VNT
static int rbr_info_vni(struct sk_buff *skb, struct net_bridge *br,
		u32 *vnis, size_t vnis_size)
{
	struct ifinfomsg *hdr;
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, 0, 0, RTM_NEWLINK, sizeof(*hdr), 0);
	if (!nlh)
		return -EMSGSIZE;

	hdr = nlmsg_data(nlh);
	hdr->ifi_family = AF_BRIDGE;
	hdr->__ifi_pad = 0;
	hdr->ifi_type = br->dev->type;
	hdr->ifi_index = br->dev->ifindex;
	hdr->ifi_flags = dev_get_flags(br->dev);
	hdr->ifi_change = 0;

	if (nla_put(skb, IFLA_TRILL_VNI, vnis_size, vnis))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

void rbr_notify_vni(struct net_bridge *br)
{
	struct net *net = dev_net(br->dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;
	int i = 0;
	u32 *vnis;
	struct vni *vni;
	size_t vnis_size;
	size_t skb_size;

	list_for_each_entry(vni, &br->vni_list, list)
		i++;
	vnis_size = sizeof(*vnis) * i;
	vnis = kzalloc(vnis_size, GFP_KERNEL);
	if (!vnis)
		goto fail;
	i = 0;
	list_for_each_entry(vni, &br->vni_list, list) {
		vnis[i] = (u_int32_t) vni->vni_id;
		i++;
	}
	skb_size = NLMSG_ALIGN(sizeof(struct ifinfomsg)) + vnis_size;
	skb = nlmsg_new(skb_size, GFP_ATOMIC);
	if (!skb)
		goto errout;

	err = rbr_info_vni(skb, br, vnis, vnis_size);
	if (err < 0) {
		err = -EMSGSIZE;
		goto errout;
	}
	kfree(vnis);

	rtnl_notify(skb, net, 0, RTNLGRP_TRILL, NULL, GFP_ATOMIC);
	return;

errout:
	kfree(vnis);
	kfree_skb(skb);
fail:
	pr_warn("rbr: failed to notify vni list\n");
	rtnl_set_sk_err(net, RTNLGRP_TRILL, err);
}
#endif
