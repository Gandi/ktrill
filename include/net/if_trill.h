#ifndef _LINUX_IF_TRILL_H_
#define _LINUX_IF_TRILL_H_

#include <linux/types.h>

/* trill_hdr structure
 *                                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                | V | R |M|op-Length| Hop Count |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|  Egress RBridge Nickname      |    Ingress RBridge Nickname   |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct trill_hdr {
	__be16 th_flags;
	__be16 th_egressnick;
	__be16 th_ingressnick;
} __packed;

static inline u16 trill_get_version(u16 trill_flags)
{
	return (trill_flags >> 14) & 0x0003;
}

static inline u16 trill_set_version(u16 trill_flags, u16 v)
{
	trill_flags |= (v & 0x0003) << 14;
	return trill_flags;
}

static inline u16 trill_get_reserved(u16 trill_flags)
{
	return (trill_flags >> 12) & 0x0003;
}

static inline u16 trill_set_reserved(u16 trill_flags, u16 v)
{
	trill_flags |= (v & 0x0003) << 12;
	return trill_flags;
}

static inline u16 trill_get_multidest(u16 trill_flags)
{
	return (trill_flags >> 11) & 0x0001;
}

static inline u16 trill_set_multidest(u16 trill_flags, u16 flag)
{
	trill_flags |= (flag & 0x0001) << 11;
	return trill_flags;
}

/* len is in 4 bytes units << 2*/
static inline size_t trill_get_optslen(u16 trill_flags)
{
	return ((trill_flags >> 6) & 0x001F) << 2;
}

static inline u16 trill_set_optslen(u16 trill_flags, u16 len)
{
	trill_flags |= ((len >> 2) & 0x001F) << 6;
	return trill_flags;
}

static inline u16 trill_get_hopcount(u16 trill_flags)
{
	return trill_flags & 0x003F;
}

static inline u16 trill_set_hopcount(u16 trill_flags, u16 count)
{
	trill_flags |= count & 0x003F;
	return trill_flags;
}

static inline void trillhdr_dec_hopcount(struct trill_hdr *trh)
{
	u8 *flags = (u8 *) &trh->th_flags;

	if (flags[1] & 0x3F)
		flags[1] -= 1;
}

static inline size_t trill_header_len(struct trill_hdr *trh)
{
	return sizeof(*trh) + trill_get_optslen(ntohs(trh->th_flags));
}
#endif /* _LINUX_IF_TRILL_H_ */
