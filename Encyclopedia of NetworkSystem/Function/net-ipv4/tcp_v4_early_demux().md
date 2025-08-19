---
Location: /net/ipv4/tcp_ipv4.c
Parameter:
  - sk_buff
Return: int
---
```c
int tcp_v4_early_demux(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	const struct iphdr *iph;
	const struct tcphdr *th;
	struct sock *sk;
	  
	if (skb->pkt_type != PACKET_HOST)
		return 0;
	  
	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct tcphdr)))
		return 0;
	
	iph = ip_hdr(skb);
	th = tcp_hdr(skb);
	  
	if (th->doff < sizeof(struct tcphdr) / 4)
		return 0;
	  
	sk = __inet_lookup_established(net, net->ipv4.tcp_death_row.hashinfo,
						iph->saddr, th->source, 
						iph->daddr, ntohs(th->dest),
						skb->skb_iif, inet_sdif(skb));
	if (sk) {
		skb->sk = sk;
		skb->destructor = sock_edemux;
		if (sk_fullsock(sk)) {
			struct dst_entry *dst = rcu_dereference(sk->sk_rx_dst);
			  
			if (dst)
				dst = dst_check(dst, 0);
			if (dst &&
				sk->sk_rx_dst_ifindex == skb->skb_iif)
				skb_dst_set_noref(skb, dst);
		}
	}
	return 0;
}
```

>ip 헤더와 tcp 헤더를 불러와서 `__inet_lookup_established()`함수를 호출한다. 이는 listen 상태인 소켓을 빠르게 찾아서 디 멀티플렉싱을 한다는 것으로 볼 수 있다. 찾은 소켓이 있다면 `skb->sk`, `skb->destructor`를 셋팅하고, 만약 full socket이라면 해당 `dst`를 `sk`에 매핑하게 되는 것이다.

---
```c
	iph = ip_hdr(skb);
	th = tcp_hdr(skb);
	  
	if (th->doff < sizeof(struct tcphdr) / 4)
		return 0;
	
	sk = __inet_lookup_established(net, net->ipv4.tcp_death_row.hashinfo,
						iph->saddr, th->source, 
						iph->daddr, ntohs(th->dest),
						skb->skb_iif, inet_sdif(skb));
```

ip 헤더와 tcp 헤더를 불러와서 `__inet_lookup_established()` 함수를 호출한다. 해당 함수에서는 ip 헤더의 source ip, destination ip, tcp 헤더의 source port, destination port, namespace 정보를 바탕으로 tcp 소켓 해시테이블을 검색해서, 이미 연결된 소켓(established)을 찾는다.

```c
	if (sk) {
		skb->sk = sk; // skb->sk 설정
		skb->destructor = sock_edemux; // skb를 해제할 때 호출할 콜백 함수 
		if (sk_fullsock(sk)) {
			struct dst_entry *dst = rcu_dereference(sk->sk_rx_dst);
			  
			if (dst) // 전에 쓴 라우팅 경로가 있는지 확인
				dst = dst_check(dst, 0);
				
			//@skb_iif: ifindex of device we arrived on
			if (dst &&
				sk->sk_rx_dst_ifindex == skb->skb_iif)
				skb_dst_set_noref(skb, dst);
		}
	}
```

이미 연결된 소켓이 있으면 `skb->sk`를 갱신한다.  이후, 소켓에 이전에 사용한 라우팅 경로가 있는지 확인한다. 즉, 이 소켓이 과거에 패킷을 송수신할 때 라우팅 테이블을 조회해서 얻었던 결과를 확인하는 것이다.

라우팅 경로가 존재하고, 소켓이 마지막으로 패킷을 받은 네트워크 인터페이스와 현재 패킷의 인터페이스가 같다면, `skb->dst`를 그 이전 라우팅 경로로 설정해 불필요한 라우팅 계산을 건너뛴다.

```c
struct dst_entry {
	struct net_device       *dev;
	struct  dst_ops	        *ops;
	unsigned long		_metrics;
	unsigned long           expires;
#ifdef CONFIG_XFRM
	struct xfrm_state	*xfrm;
#else
	void			*__pad1;
#endif
	int			(*input)(struct sk_buff *); 
	int			(*output)(struct net *net, struct sock *sk, struct sk_buff *skb);

	unsigned short		flags;
#define DST_NOXFRM		0x0002
#define DST_NOPOLICY		0x0004
#define DST_NOCOUNT		0x0008
#define DST_FAKE_RTABLE		0x0010
#define DST_XFRM_TUNNEL		0x0020
#define DST_XFRM_QUEUE		0x0040
#define DST_METADATA		0x0080

	/* A non-zero value of dst->obsolete forces by-hand validation
	 * of the route entry.  Positive values are set by the generic
	 * dst layer to indicate that the entry has been forcefully
	 * destroyed.
	 *
	 * Negative values are used by the implementation layer code to
	 * force invocation of the dst_ops->check() method.
	 */
	short			obsolete;
#define DST_OBSOLETE_NONE	0
#define DST_OBSOLETE_DEAD	2
#define DST_OBSOLETE_FORCE_CHK	-1
#define DST_OBSOLETE_KILL	-2
	unsigned short		header_len;	/* more space at head required */
	unsigned short		trailer_len;	/* space to reserve at tail */

	/*
	 * __rcuref wants to be on a different cache line from
	 * input/output/ops or performance tanks badly
	 */
#ifdef CONFIG_64BIT
	rcuref_t		__rcuref;	/* 64-bit offset 64 */
#endif
	int			__use;
	unsigned long		lastuse;
	struct rcu_head		rcu_head;
	short			error;
	short			__pad;
	__u32			tclassid;
#ifndef CONFIG_64BIT
	struct lwtunnel_state   *lwtstate;
	rcuref_t		__rcuref;	/* 32-bit offset 64 */
#endif
	netdevice_tracker	dev_tracker;

	/*
	 * Used by rtable and rt6_info. Moves lwtstate into the next cache
	 * line on 64bit so that lwtstate does not cause false sharing with
	 * __rcuref under contention of __rcuref. This also puts the
	 * frequently accessed members of rtable and rt6_info out of the
	 * __rcuref cache line.
	 */
	struct list_head	rt_uncached;
	struct uncached_list	*rt_uncached_list;
#ifdef CONFIG_64BIT
	struct lwtunnel_state   *lwtstate;
#endif
};

struct dst_metrics {
	u32		metrics[RTAX_MAX];
	refcount_t	refcnt;
} __aligned(4);		/* Low pointer bits contain DST_METRICS_FLAGS */
extern const struct dst_metrics dst_default_metrics;
```