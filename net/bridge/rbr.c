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
	if (likely(old))
		kfree(old);
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
