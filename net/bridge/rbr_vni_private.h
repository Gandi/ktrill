/*
 *	Generic parts
 *	Linux ethernet Rbridge VNI extension
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

#ifndef RBR_VNI
#define RBR_VNI

#include "rbr_private.h"

struct vni {
	struct list_head	port_list;
	struct list_head	list;
	struct net_bridge	*br;
	struct rcu_head		rcu;
	u32			vni_id;
};
#endif /* RBR_VNI */
