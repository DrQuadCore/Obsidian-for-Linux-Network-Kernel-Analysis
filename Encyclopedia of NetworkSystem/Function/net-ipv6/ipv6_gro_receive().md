---
Parameter:
  - list_head
  - sk_buff
Return: sk_buff
Location: /net/ipv6/ip6_offload.c
---

```c title=ipv6_gro_receive()
INDIRECT_CALLABLE_SCOPE struct sk_buff *ipv6_gro_receive(struct list_head *head,
							 struct sk_buff *skb)
{
	const struct net_offload *ops;
	struct sk_buff *pp = NULL;
	struct sk_buff *p;
	struct ipv6hdr *iph;
	unsigned int nlen;
	unsigned int hlen;
	unsigned int off;
	u16 flush = 1; 
	int proto;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*iph);
	iph = skb_gro_header(skb, hlen, off);
	if (unlikely(!iph))
		goto out;

	skb_set_network_header(skb, off);
	NAPI_GRO_CB(skb)->inner_network_offset = off;

	flush += ntohs(iph->payload_len) != skb->len - hlen;

	proto = iph->nexthdr;
	ops = rcu_dereference(inet6_offloads[proto]);
	if (!ops || !ops->callbacks.gro_receive) {
		proto = ipv6_gro_pull_exthdrs(skb, hlen, proto);

		ops = rcu_dereference(inet6_offloads[proto]);
		if (!ops || !ops->callbacks.gro_receive)
			goto out;

		iph = skb_gro_network_header(skb);
	} else {
		skb_gro_pull(skb, sizeof(*iph));
	}

	skb_set_transport_header(skb, skb_gro_offset(skb));

	NAPI_GRO_CB(skb)->proto = proto;

	flush--;
	nlen = skb_network_header_len(skb);

	list_for_each_entry(p, head, list) {
		const struct ipv6hdr *iph2;
		__be32 first_word; /* <Version:4><Traffic_Class:8><Flow_Label:20> */

		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		iph2 = (struct ipv6hdr *)(p->data + off);
		first_word = *(__be32 *)iph ^ *(__be32 *)iph2;

		/* All fields must match except length and Traffic Class.
		 * XXX skbs on the gro_list have all been parsed and pulled
		 * already so we don't need to compare nlen
		 * (nlen != (sizeof(*iph2) + ipv6_exthdrs_len(iph2, &ops)))
		 * memcmp() alone below is sufficient, right?
		 */
		 if ((first_word & htonl(0xF00FFFFF)) ||
		     !ipv6_addr_equal(&iph->saddr, &iph2->saddr) ||
		     !ipv6_addr_equal(&iph->daddr, &iph2->daddr) ||
		     iph->nexthdr != iph2->nexthdr) {
not_same_flow:
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
		if (unlikely(nlen > sizeof(struct ipv6hdr))) {
			if (memcmp(iph + 1, iph2 + 1,
				   nlen - sizeof(struct ipv6hdr)))
				goto not_same_flow;
		}
		/* flush if Traffic Class fields are different */
		NAPI_GRO_CB(p)->flush |= !!((first_word & htonl(0x0FF00000)) |
			(__force __be32)(iph->hop_limit ^ iph2->hop_limit));
		NAPI_GRO_CB(p)->flush |= flush;

		/* If the previous IP ID value was based on an atomic
		 * datagram we can overwrite the value and ignore it.
		 */
		if (NAPI_GRO_CB(skb)->is_atomic)
			NAPI_GRO_CB(p)->flush_id = 0;
	}

	NAPI_GRO_CB(skb)->is_atomic = true;
	NAPI_GRO_CB(skb)->flush |= flush;

	skb_gro_postpull_rcsum(skb, iph, nlen);

	pp = indirect_call_gro_receive_l4(tcp6_gro_receive, udp6_gro_receive,
					 ops->callbacks.gro_receive, head, skb); // [[Encyclopedia of NetworkSystem/Function/net-ipv6/tcp6_gro_receive().md|tcp6_gro_receive()]]

out:
	skb_gro_flush_final(skb, pp, flush);

	return pp;
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv6/tcp6_gro_receive().md|tcp6_gro_receive()]]
