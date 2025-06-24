---
Parameter:
  - list_head
  - sk_buff
Return: sk_buff
Location: /net/ipv4/tcp_offload.c
---

```c title=tcp4_gro_receive()
INDIRECT_CALLABLE_SCOPE
struct sk_buff *tcp4_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	/* Don't bother verifying checksum if we're going to flush anyway. */
	if (!NAPI_GRO_CB(skb)->flush &&
	    skb_gro_checksum_validate(skb, IPPROTO_TCP,
				      inet_gro_compute_pseudo)) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	return tcp_gro_receive(head, skb); // [[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_gro_receive().md|tcp_gro_receive()]]
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_gro_receive().md|tcp_gro_receive()]]

> 간단하게 flush가 필요한지 여부와 checksum이 유효한지 여부를 따져서 더 processing이 진행되는지 확인하는 If문이 하나가 있고, 아니라면 tcp_gro_receive()함수를 호출하여 계속 진행하게 된다.