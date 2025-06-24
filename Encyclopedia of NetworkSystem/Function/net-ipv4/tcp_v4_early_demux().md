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

[[__inet_lookup_established()]]