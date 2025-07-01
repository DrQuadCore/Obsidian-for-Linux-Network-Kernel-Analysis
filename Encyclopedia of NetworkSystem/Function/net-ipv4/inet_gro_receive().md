---
Parameter:
  - list_head
  - sk_buff
Return: sk_buff
Location: /net/ipv4/af_inet.c
---

```c title=inet_gro_receive()
struct sk_buff *inet_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	const struct net_offload *ops;
	struct sk_buff *pp = NULL;
	const struct iphdr *iph;
	struct sk_buff *p;
	unsigned int hlen;
	unsigned int off;
	unsigned int id;
	int flush = 1;
	int proto;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*iph);
	iph = skb_gro_header(skb, hlen, off);
	if (unlikely(!iph))
		goto out;

	proto = iph->protocol;

	ops = rcu_dereference(inet_offloads[proto]);
	if (!ops || !ops->callbacks.gro_receive)
		goto out;

	if (*(u8 *)iph != 0x45)
		goto out;

	if (ip_is_fragment(iph))
		goto out;

	if (unlikely(ip_fast_csum((u8 *)iph, 5)))
		goto out;

	NAPI_GRO_CB(skb)->proto = proto;
	id = ntohl(*(__be32 *)&iph->id);
	flush = (u16)((ntohl(*(__be32 *)iph) ^ skb_gro_len(skb)) | (id & ~IP_DF));
	id >>= 16;

	list_for_each_entry(p, head, list) {
		struct iphdr *iph2;
		u16 flush_id;

		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		iph2 = (struct iphdr *)(p->data + off);
		/* The above works because, with the exception of the top
		 * (inner most) layer, we only aggregate pkts with the same
		 * hdr length so all the hdrs we'll need to verify will start
		 * at the same offset.
		 */
		if ((iph->protocol ^ iph2->protocol) |
		    ((__force u32)iph->saddr ^ (__force u32)iph2->saddr) |
		    ((__force u32)iph->daddr ^ (__force u32)iph2->daddr)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* All fields must match except length and checksum. */
		NAPI_GRO_CB(p)->flush |=
			(iph->ttl ^ iph2->ttl) |
			(iph->tos ^ iph2->tos) |
			((iph->frag_off ^ iph2->frag_off) & htons(IP_DF));

		NAPI_GRO_CB(p)->flush |= flush;

		/* We need to store of the IP ID check to be included later
		 * when we can verify that this packet does in fact belong
		 * to a given flow.
		 */
		flush_id = (u16)(id - ntohs(iph2->id));

		/* This bit of code makes it much easier for us to identify
		 * the cases where we are doing atomic vs non-atomic IP ID
		 * checks.  Specifically an atomic check can return IP ID
		 * values 0 - 0xFFFF, while a non-atomic check can only
		 * return 0 or 0xFFFF.
		 */
		if (!NAPI_GRO_CB(p)->is_atomic ||
		    !(iph->frag_off & htons(IP_DF))) {
			flush_id ^= NAPI_GRO_CB(p)->count;
			flush_id = flush_id ? 0xFFFF : 0;
		}

		/* If the previous IP ID value was based on an atomic
		 * datagram we can overwrite the value and ignore it.
		 */
		if (NAPI_GRO_CB(skb)->is_atomic)
			NAPI_GRO_CB(p)->flush_id = flush_id;
		else
			NAPI_GRO_CB(p)->flush_id |= flush_id;
	}

	NAPI_GRO_CB(skb)->is_atomic = !!(iph->frag_off & htons(IP_DF));
	NAPI_GRO_CB(skb)->flush |= flush;
	skb_set_network_header(skb, off);
	/* The above will be needed by the transport layer if there is one
	 * immediately following this IP hdr.
	 */
	NAPI_GRO_CB(skb)->inner_network_offset = off;

	/* Note : No need to call skb_gro_postpull_rcsum() here,
	 * as we already checked checksum over ipv4 header was 0
	 */
	skb_gro_pull(skb, sizeof(*iph));
	skb_set_transport_header(skb, skb_gro_offset(skb));

	pp = indirect_call_gro_receive(tcp4_gro_receive, udp4_gro_receive,
				       ops->callbacks.gro_receive, head, skb); // [[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp4_gro_receive().md|tcp4_gro_receive()]]

out:
	skb_gro_flush_final(skb, pp, flush);

	return pp;
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp4_gro_receive().md|tcp4_gro_receive()]]

> ipv4 에서 gro receive를 처리하는 함수이다. indirect call을 통해서 호출되게 되며, 기존의 gro_list와 병합하려는 패킷이 서로 맞는지 <span style="background:#fff88f">L3에서의 필요한 처리들과 검사들을 진행하게 되며</span>, 여기서는 출발지 주소와 목적지 주소가 같은지, ttl과 tos (time to live, type of service)등이 같은지 여부를 통해 병합해도 되는 패킷인지 검사하게 된다. 이 때 병합하려는 패킷들의 모든 리스트를 검사하게 된다. 그 다음 L3 헤더 길이 만큼 skb_gro_pull을 통해 data_offset에다가 그 길이만큼 더하여 <span style="background:#fff88f">다음 L4 헤더를 볼 수 있게 한다.</span>