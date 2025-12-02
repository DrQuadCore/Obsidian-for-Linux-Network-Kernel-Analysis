---
Parameter:
  - net
  - flowi4
  - sock
  - __be32
  - __be32
  - __be16
  - __be16
  - __u8
  - __u8
  - int
Return: rtable
Location: /include/net/route.h
---
```c
static inline struct rtable *ip_route_output_ports(struct net *net, 
						   struct flowi4 *fl4,
						   const struct sock *sk,
						   __be32 daddr, __be32 saddr,
						   __be16 dport, __be16 sport,
						   __u8 proto, __u8 tos, int oif)
{
	flowi4_init_output(fl4, oif, sk ? READ_ONCE(sk->sk_mark) : 0, tos,
			   sk ? ip_sock_rt_scope(sk) : RT_SCOPE_UNIVERSE,
			   proto, sk ? inet_sk_flowi_flags(sk) : 0,
			   daddr, saddr, dport, sport, sock_net_uid(net, sk)); // [[Encyclopedia of NetworkSystem/Function/include-net/flowi4_init_output()|flowi4_init_output()]] // fl4 초기화
	if (sk)
		security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
	return ip_route_output_flow(net, fl4, sk); // [[ip_route_output_flow()]]
}

```

---

struct flowi4 라는 구조체가 등장한다. 

```c
struct flowi4 {
	struct flowi_common	__fl_common;
#define flowi4_oif		__fl_common.flowic_oif
#define flowi4_iif		__fl_common.flowic_iif
#define flowi4_l3mdev		__fl_common.flowic_l3mdev
#define flowi4_mark		__fl_common.flowic_mark
#define flowi4_tos		__fl_common.flowic_tos
#define flowi4_scope		__fl_common.flowic_scope
#define flowi4_proto		__fl_common.flowic_proto
#define flowi4_flags		__fl_common.flowic_flags
#define flowi4_secid		__fl_common.flowic_secid
#define flowi4_tun_key		__fl_common.flowic_tun_key
#define flowi4_uid		__fl_common.flowic_uid
#define flowi4_multipath_hash	__fl_common.flowic_multipath_hash

	/* (saddr,daddr) must be grouped, same order as in IP header */
	__be32			saddr;
	__be32			daddr;

	union flowi_uli		uli;
#define fl4_sport		uli.ports.sport
#define fl4_dport		uli.ports.dport
#define fl4_icmp_type		uli.icmpt.type
#define fl4_icmp_code		uli.icmpt.code
#define fl4_mh_type		uli.mht.type
#define fl4_gre_key		uli.gre_key
} __attribute__((__aligned__(BITS_PER_LONG/8)));
```

flowi4 구조체는 위와 같이 source address, destination address, protocol 등을 비롯한 필드로 구성돼 있다. 이후 FIB 테이블을 lookup 해서 얻은 라우팅 엔트리를 사용할 수 있는지 판단할 때 사용한다.


