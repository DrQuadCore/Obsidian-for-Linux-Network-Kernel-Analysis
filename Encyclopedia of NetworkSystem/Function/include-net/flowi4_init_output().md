---
Parameter:
  - flowi4
  - int
  - __u32
  - __u8
  - __u8
  - __be32
  - __be32_
  - __be16
  - __be16
  - kuid_t
Return: void
Location: /net/flow.h
---
```c
static inline void flowi4_init_output(struct flowi4 *fl4, int oif,
				      __u32 mark, __u8 tos, __u8 scope,
				      __u8 proto, __u8 flags,
				      __be32 daddr, __be32 saddr,
				      __be16 dport, __be16 sport,
				      kuid_t uid)
{
	fl4->flowi4_oif = oif;
	fl4->flowi4_iif = LOOPBACK_IFINDEX;
	fl4->flowi4_l3mdev = 0;
	fl4->flowi4_mark = mark;
	fl4->flowi4_tos = tos;
	fl4->flowi4_scope = scope;
	fl4->flowi4_proto = proto;
	fl4->flowi4_flags = flags;
	fl4->flowi4_secid = 0;
	fl4->flowi4_tun_key.tun_id = 0;
	fl4->flowi4_uid = uid;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->fl4_dport = dport;
	fl4->fl4_sport = sport;
	fl4->flowi4_multipath_hash = 0;
}

```

