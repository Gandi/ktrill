#ifndef _RBR_PRIVATE_H
#define _RBR_PRIVATE_H

#include <linux/atomic.h>
#ifdef CONFIG_TRILL_VNT
#include "rbr_vni_private.h"
#endif

#define	RBRIDGE_NICKNAME_MIN	0x0000
#define	RBRIDGE_NICKNAME_MAX	0xFFFF

/* Define well-known nicknames */
#define	RBRIDGE_NICKNAME_NONE	RBRIDGE_NICKNAME_MIN
#define	RBRIDGE_NICKNAME_UNUSED	RBRIDGE_NICKNAME_MAX

#define	TRILL_PROTOCOL_VERS 0	/* th_version */
#define	TRILL_DEFAULT_HOPS 21	/* th_hopcount */
#define VALID_NICK(n)	((n) != RBRIDGE_NICKNAME_NONE && \
			(n) != RBRIDGE_NICKNAME_UNUSED)

struct rbr_nickinfo {
	/* Nickname of the RBridge */
	u16 nick;
	/* Next-hop SNPA address to reach this RBridge */
	u8 adjsnpa[ETH_ALEN];
	/* Link on our system to use to reach next-hop */
	u32 linkid;
	/* Num of *our* adjacencies on a tree rooted at this RBridge */
	u16 adjcount;
	/* Num of distribution tree root nicks chosen by this RBridge */
	u16 dtrootcount;
	/* Variable size bytes to store adjacency nicks, distribution
	 * tree roots. Adjacency nicks and
	 * distribution tree roots are 16-bit fields.
	 */
};

struct rbr_node {
	struct rbr_nickinfo *rbr_ni;
	atomic_t refs;		/* reference count */
};

struct rbr {
	u16 nick;		/* our nickname */
	u16 treeroot;	/* tree root nickname */
	struct rbr_node *rbr_nodes[RBRIDGE_NICKNAME_MAX];
	struct net_bridge *br;	/* back pointer */
};

static inline void rbr_node_free(struct rbr_node *rbr_node)
{
	if (likely(rbr_node)) {
		kfree(rbr_node->rbr_ni);
		kfree(rbr_node);
	}
}

static inline void rbr_node_get(struct rbr_node *rbr_node)
{
	if (likely(rbr_node))
		atomic_inc(&rbr_node->refs);
}

static inline void rbr_node_put(struct rbr_node *rbr_node)
{
	if (rbr_node && unlikely(atomic_dec_and_test(&rbr_node->refs)))
		rbr_node_free(rbr_node);
}

int set_treeroot(struct rbr *rbr, uint16_t treeroot);
struct rbr_node *rbr_find_node(struct rbr *rbr, __u16 nickname);

/* Access the adjacency nick list at the end of rbr_nickinfo */
#define	RBR_NI_ADJNICKSPTR(v) ((u16 *)((struct rbr_nickinfo *)(v) + 1))
#define	RBR_NI_ADJNICK(v, n) (RBR_NI_ADJNICKSPTR(v)[(n)])

/* Access the DT root nick list in rbr_nickinfo after adjacency nicks */
#define	RBR_NI_DTROOTNICKSPTR(v) (RBR_NI_ADJNICKSPTR(v) + (v)->adjcount)
#define	RBR_NI_DTROOTNICK(v, n) (RBR_NI_DTROOTNICKSPTR(v)[(n)])

#define	RBR_NI_TOTALSIZE(v) (\
		(sizeof(struct rbr_nickinfo)) + \
		(sizeof(u16) * (v)->adjcount) + \
		(sizeof(u16) * (v)->dtrootcount)\
		)
#endif
