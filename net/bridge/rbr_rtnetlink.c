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
	}
	if (data[IFLA_TRILL_ROOT]) {
		if (!br->rbr)
			return -EINVAL;
		nick = nla_get_u16(data[IFLA_TRILL_ROOT]);
		err = set_treeroot(br->rbr, htons(nick));
	}

	return 0;
fail:
	pr_warn("rbr_set_data FAILED\n");
	return err;
}
