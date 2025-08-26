
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

**inet_steal_sock()**
```c title=inet_steal_sock()
// include/net/inet_hashtables.h
static inline
struct sock *inet_steal_sock(struct net *net, struct sk_buff *skb, int doff,
			     const __be32 saddr, const __be16 sport,
			     const __be32 daddr, const __be16 dport,
			     bool *refcounted, inet_ehashfn_t *ehashfn)
{
	struct sock *sk, *reuse_sk;
	bool prefetched;

	sk = skb_steal_sock(skb, refcounted, &prefetched);
	if (!sk)
		return NULL;

	if (!prefetched || !sk_fullsock(sk))
		return sk;

	if (sk->sk_protocol == IPPROTO_TCP) {
		if (sk->sk_state != TCP_LISTEN)
			return sk;
	} else if (sk->sk_protocol == IPPROTO_UDP) {
		if (sk->sk_state != TCP_CLOSE)
			return sk;
	} else {
		return sk;
	}

	reuse_sk = inet_lookup_reuseport(net, sk, skb, doff,
					 saddr, sport, daddr, ntohs(dport),
					 ehashfn);
	if (!reuse_sk)
		return sk;

	/* We've chosen a new reuseport sock which is never refcounted. This
	 * implies that sk also isn't refcounted.
	 */
	WARN_ON_ONCE(*refcounted);

	return reuse_sk;
}
```
매개변수로 받은 skb에 연결된 `sock` 구조체를 가져오려고 시도

**__inet_lookup()**
```c title=__inet_lookup()
// include/net/inet_hashtables.h
static inline struct sock *inet_lookup(struct net *net,
				       struct inet_hashinfo *hashinfo,
				       struct sk_buff *skb, int doff,
				       const __be32 saddr, const __be16 sport,
				       const __be32 daddr, const __be16 dport,
				       const int dif)
{
	struct sock *sk;
	bool refcounted;

	sk = __inet_lookup(net, hashinfo, skb, doff, saddr, sport, daddr,
			   dport, dif, 0, &refcounted);

	if (sk && !refcounted && !refcount_inc_not_zero(&sk->sk_refcnt))
		sk = NULL;
	return sk;
}
```
주어진 시작, 도착지의 IP 주소, 포트번호, 인터페이스 정보로 TCP/UDP 해시 테이블에서 일치하는 `sock`을 찾아 반환

