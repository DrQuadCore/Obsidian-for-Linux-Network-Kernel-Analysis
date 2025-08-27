
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

**1. inet_steal_sock()**
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
1. 매개변수로 받은 skb에 연결된 `sock` 구조체를 가져오려고 시도(`skb_steal_sock()`)
2. BPF로 sk가 이미 할당되었거나 완전한 소켓이 아니라면 sk 반환
3. TCP이면서 LISTEN 상태가 아니거나, UDP이면서 CLOSE 상태가 아니거나, TCP도 UDP도 아니면 sk반환
4. 이후는 재분배 대상이므로(`TCP LISTEN` 또는 `UDP TCP_CLOSE`인 경우) 대체 소켓을 찾았으면(`inet_lookup_reuseport()`) 반환, 못 찾았으면 sk 반환

**1.1. skb_steal_sock()**
```c title=skb_steal_sock()
/**
 * skb_steal_sock - steal a socket from an sk_buff
 * @skb: sk_buff to steal the socket from
 * @refcounted: is set to true if the socket is reference-counted
 * @prefetched: is set to true if the socket was assigned from bpf
 */
static inline struct sock *skb_steal_sock(struct sk_buff *skb,
					  bool *refcounted, bool *prefetched)
{
	struct sock *sk = skb->sk;

	if (!sk) {
		*prefetched = false;
		*refcounted = false;
		return NULL;
	}

	*prefetched = skb_sk_is_prefetched(skb);
	if (*prefetched) {
#if IS_ENABLED(CONFIG_SYN_COOKIES)
		if (sk->sk_state == TCP_NEW_SYN_RECV && inet_reqsk(sk)->syncookie) {
			struct request_sock *req = inet_reqsk(sk);

			*refcounted = false;
			sk = req->rsk_listener;
			req->rsk_listener = NULL;
			return sk;
		}
#endif
		*refcounted = sk_is_refcounted(sk);
	} else {
		*refcounted = true;
	}

	skb->destructor = NULL;
	skb->sk = NULL;
	return sk;
}
```
1. `sk_buff` 구조체에서 `sock`를 들고 오고 BPF 사용 여부 확인
2. sk_buff에서 소켓 참조하는 멤버 변수를 NULL로 초기화하고 sk 반환
---

**2. __inet_lookup()**
```c title=__inet_lookup()
// include/net/inet_hashtables.h
static inline struct sock *__inet_lookup(struct net *net,
					 struct inet_hashinfo *hashinfo,
					 struct sk_buff *skb, int doff,
					 const __be32 saddr, const __be16 sport,
					 const __be32 daddr, const __be16 dport,
					 const int dif, const int sdif,
					 bool *refcounted)
{
	u16 hnum = ntohs(dport);
	struct sock *sk;

	sk = __inet_lookup_established(net, hashinfo, saddr, sport,
				       daddr, hnum, dif, sdif);
	*refcounted = true;
	if (sk)
		return sk;
	*refcounted = false;
	return __inet_lookup_listener(net, hashinfo, skb, doff, saddr,
				      sport, daddr, hnum, dif, sdif);
}
```
1. 주어진 시작, 도착지의 IP 주소, 포트번호, 인터페이스 정보로 TCP/UDP 해시 테이블에서 일치하는 `sock`을 찾기(`__inet_lookup_established()`)
2. 이미 연결된 소켓을 찾으면 refcounted를 true로 하고 소켓 반환
3. 못  찾았으면 refcounted는 false로 하고 리스너 소켓을 찾아서(`__inet_lookup_listener()`) 반환