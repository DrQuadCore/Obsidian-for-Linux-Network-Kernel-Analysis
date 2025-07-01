---
Parameter:
  - sk_buff
  - int
Return: int
Location: /net/ipv6/tcpv6_offload.c
---

```c title=tcp6_gro_complete()
INDIRECT_CALLABLE_SCOPE int tcp6_gro_complete(struct sk_buff *skb, int thoff)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);

	th->check = ~tcp_v6_check(skb->len - thoff, &iph->saddr,
				  &iph->daddr, 0);
	skb_shinfo(skb)->gso_type |= SKB_GSO_TCPV6;

	tcp_gro_complete(skb); // [[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_gro_complete().md|tcp_gro_complete()]]
	return 0;
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_gro_complete().md|tcp_gro_complete()]]
