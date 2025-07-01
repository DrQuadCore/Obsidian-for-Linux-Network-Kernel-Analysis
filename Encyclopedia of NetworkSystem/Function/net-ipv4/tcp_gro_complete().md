---
Parameter:
  - sk_buff
Return: void
Location: /net/ipv4/tcp_offload.c
---

```c title=tcp_gro_complete()
void tcp_gro_complete(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct skb_shared_info *shinfo;

	if (skb->encapsulation)
		skb->inner_transport_header = skb->transport_header;

	skb->csum_start = (unsigned char *)th - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	shinfo = skb_shinfo(skb);
	shinfo->gso_segs = NAPI_GRO_CB(skb)->count;

	if (th->cwr)
		shinfo->gso_type |= SKB_GSO_TCP_ECN;
}
```

> skb와 shinfo에 대하여 gro가 완료되었을 때를 기준으로 정보를 업데이트 해주는 함수이다. 따로 반환값은 존재하지 않았다.