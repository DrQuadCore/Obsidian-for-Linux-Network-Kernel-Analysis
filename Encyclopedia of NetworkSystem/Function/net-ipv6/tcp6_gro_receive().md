---
Parameter:
  - list_head
  - sk_buff
Return: sk_buff
Location: /net/ipv6/tcp6_offload.c
---

```c title=tcp6_gro_receive()
INDIRECT_CALLABLE_SCOPE
struct sk_buff *tcp6_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	/* Don't bother verifying checksum if we're going to flush anyway. */
	if (!NAPI_GRO_CB(skb)->flush &&
	    skb_gro_checksum_validate(skb, IPPROTO_TCP,
				      ip6_gro_compute_pseudo)) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	return tcp_gro_receive(head, skb); // [[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_gro_receive().md|tcp_gro_receive()]]
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_gro_receive().md|tcp_gro_receive()]]
