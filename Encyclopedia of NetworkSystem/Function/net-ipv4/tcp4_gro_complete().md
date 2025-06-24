---
Parameter:
  - sk_buff
  - int
Return: int
Location: /net/ipv4/tcp_offload.c
---

```c title=tcp4_gro_complete()
INDIRECT_CALLABLE_SCOPE int tcp4_gro_complete(struct sk_buff *skb, int thoff)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);

	th->check = ~tcp_v4_check(skb->len - thoff, iph->saddr,
				  iph->daddr, 0);

	skb_shinfo(skb)->gso_type |= SKB_GSO_TCPV4 |
			(NAPI_GRO_CB(skb)->is_atomic * SKB_GSO_TCP_FIXEDID);

	tcp_gro_complete(skb); // [[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_gro_complete().md|tcp_gro_complete()]]
	return 0;
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_gro_complete().md|tcp_gro_complete()]]

> 여기도 단순하게 checksum 유효성만 검사하고, tcp_gro_receive()를 호출해주는 과정만 존재한다.