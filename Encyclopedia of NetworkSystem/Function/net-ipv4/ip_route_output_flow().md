---
Parameter:
  - net
  - flowi4
  - sock
Return: rtable
Location: /net/ipv4/route.c
---
```c
struct rtable *ip_route_output_flow(struct net *net, struct flowi4 *flp4,
				    const struct sock *sk)
{
	struct rtable *rt = __ip_route_output_key(net, flp4);

	if (IS_ERR(rt))
		return rt;

	if (flp4->flowi4_proto) {
		flp4->flowi4_oif = rt->dst.dev->ifindex;
		rt = (struct rtable *)xfrm_lookup_route(net, &rt->dst,
							flowi4_to_flowi(flp4),
							sk, 0);
	}

	return rt;
}
```

---

```c
static inline struct rtable *__ip_route_output_key(struct net *net,
						   struct flowi4 *flp)
{
	return ip_route_output_key_hash(net, flp, NULL);
}
```

```c
struct rtable *ip_route_output_key_hash(struct net *net, struct flowi4 *fl4,
					const struct sk_buff *skb)
{
	struct fib_result res = { // FIB lookup 결과를 담는 구조체 
		.type		= RTN_UNSPEC, // route 타입
		.fi		= NULL,
		.table		= NULL, // 어떤 라우팅 테이블에서 나온 결과인지
		.tclassid	= 0,
	}; 
	struct rtable *rth;

	fl4->flowi4_iif = LOOPBACK_IFINDEX;
	ip_rt_fix_tos(fl4);

	rcu_read_lock();
	rth = ip_route_output_key_hash_rcu(net, fl4, &res, skb); // [[ip_route_output_key_hash_rcu()]]
	rcu_read_unlock();

	return rth;
}
```