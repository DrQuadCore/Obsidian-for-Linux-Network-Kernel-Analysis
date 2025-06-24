```c
static inline struct sock *__inet_lookup_skb(struct inet_hashinfo *hashinfo,
					     struct sk_buff *skb,
					     int doff,
					     const __be16 sport,
					     const __be16 dport,
					     const int sdif,
					     bool *refcounted)
{
	struct net *net = dev_net(skb_dst(skb)->dev);
	const struct iphdr *iph = ip_hdr(skb);
	struct sock *sk;

	sk = inet_steal_sock(net, skb, doff, iph->saddr, sport, iph->daddr, dport,
			     refcounted, inet_ehashfn);
	if (IS_ERR(sk))
		return NULL;
	if (sk)
		return sk;

	return __inet_lookup(net, hashinfo, skb,
			     doff, iph->saddr, sport,
			     iph->daddr, dport, inet_iif(skb), sdif,
			     refcounted);
}
```

skb에 맞는 socket을 찾아주는 함수이다. 
1. inet_steal_sock() 실행 후, sk가 존재한다면 리턴
2. steal 에 실패한다면 \_\_inet_lookup() 실행해서 리턴

[[\_\_inet_lookup()]]


