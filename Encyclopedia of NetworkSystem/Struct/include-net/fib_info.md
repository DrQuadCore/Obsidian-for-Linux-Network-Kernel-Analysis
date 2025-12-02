---
Location: /net/ipv4/ip_fib.h
---

```c
struct fib_info {
	struct hlist_node	fib_hash;
	struct hlist_node	fib_lhash;
	struct list_head	nh_list;
	struct net		*fib_net; // The network namespace 
	refcount_t		fib_treeref; // A reference counter that represents the number of fib_alias objects
	refcount_t		fib_clntref; // A reference counter that is incremented by the fib_create_info() method
	unsigned int		fib_flags;
	unsigned char		fib_dead; // whether it is permitted to free the fib_info
	unsigned char		fib_protocol; // the routing protocol identifier 
	unsigned char		fib_scope; // scope of the destination address
	unsigned char		fib_type; // The type of the route.
	__be32			fib_prefsrc;
	u32			fib_tb_id;
	u32			fib_priority;
	struct dst_metrics	*fib_metrics;
#define fib_mtu fib_metrics->metrics[RTAX_MTU-1]
#define fib_window fib_metrics->metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics->metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics->metrics[RTAX_ADVMSS-1]
	int			fib_nhs; // The number of nexthops
	bool			fib_nh_is_v6;
	bool			nh_updated;
	bool			pfsrc_removed;
	struct nexthop		*nh; // next hop
	struct rcu_head		rcu;
	struct fib_nh		fib_nh[] __counted_by(fib_nhs);
};

```

**scope**
-  host (RT_SCOPE_HOST): The node cannot communicate with the other network nodes. 
The loopback address has scope host. (자기 자신 안에서만)
 - global (RT_SCOPE_UNIVERSE): The address can be used anywhere. This is the most 
common case. (어디서든)
 - link (RT_SCOPE_LINK): This address can be accessed only from directly attached hosts. (같은 link, 브로드캐스트 도메인에서만)
 - site (RT_SCOPE_SITE): This is used in IPv6 only (I discuss it in Chapter 8).
 - nowhere (RT_SCOPE_NOWHERE): Destination doesn't exist. (도달할 수 없는 범위)