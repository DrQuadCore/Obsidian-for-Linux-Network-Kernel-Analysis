---
Parameter:
  - sk_buff
  - int
Return: int
Location: /net/ipv6/ip6_offload.c
---

```c title=ipv6_gro_complete()
INDIRECT_CALLABLE_SCOPE int ipv6_gro_complete(struct sk_buff *skb, int nhoff)
{
	const struct net_offload *ops;
	struct ipv6hdr *iph;
	int err = -ENOSYS;
	u32 payload_len;

	if (skb->encapsulation) {
		skb_set_inner_protocol(skb, cpu_to_be16(ETH_P_IPV6));
		skb_set_inner_network_header(skb, nhoff);
	}

	payload_len = skb->len - nhoff - sizeof(*iph);
	if (unlikely(payload_len > IPV6_MAXPLEN)) {
		struct hop_jumbo_hdr *hop_jumbo;
		int hoplen = sizeof(*hop_jumbo);

		/* Move network header left */
		memmove(skb_mac_header(skb) - hoplen, skb_mac_header(skb),
			skb->transport_header - skb->mac_header);
		skb->data -= hoplen;
		skb->len += hoplen;
		skb->mac_header -= hoplen;
		skb->network_header -= hoplen;
		iph = (struct ipv6hdr *)(skb->data + nhoff);
		hop_jumbo = (struct hop_jumbo_hdr *)(iph + 1);

		/* Build hop-by-hop options */
		hop_jumbo->nexthdr = iph->nexthdr;
		hop_jumbo->hdrlen = 0;
		hop_jumbo->tlv_type = IPV6_TLV_JUMBO;
		hop_jumbo->tlv_len = 4;
		hop_jumbo->jumbo_payload_len = htonl(payload_len + hoplen);

		iph->nexthdr = NEXTHDR_HOP;
		iph->payload_len = 0;
	} else {
		iph = (struct ipv6hdr *)(skb->data + nhoff);
		iph->payload_len = htons(payload_len);
	}

	nhoff += sizeof(*iph) + ipv6_exthdrs_len(iph, &ops);
	if (WARN_ON(!ops || !ops->callbacks.gro_complete))
		goto out;

	err = INDIRECT_CALL_L4(ops->callbacks.gro_complete, tcp6_gro_complete,
			       udp6_gro_complete, skb, nhoff); // [[Encyclopedia of NetworkSystem/Function/net-ipv6/tcp6_gro_complete().md|tcp6_gro_complete()]]

out:
	return err;
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv6/tcp6_gro_complete().md|tcp6_gro_complete()]]
