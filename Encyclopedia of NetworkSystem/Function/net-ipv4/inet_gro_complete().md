---
Parameter:
  - sk_buff
  - int
Return: int
Location: /net/ipv4/af_inet.c
---

```c title=inet_gro_complete()
int inet_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct iphdr *iph = (struct iphdr *)(skb->data + nhoff);
	const struct net_offload *ops;
	__be16 totlen = iph->tot_len;
	int proto = iph->protocol;
	int err = -ENOSYS;

	if (skb->encapsulation) {
		skb_set_inner_protocol(skb, cpu_to_be16(ETH_P_IP));
		skb_set_inner_network_header(skb, nhoff);
	}

	iph_set_totlen(iph, skb->len - nhoff);
	csum_replace2(&iph->check, totlen, iph->tot_len);

	ops = rcu_dereference(inet_offloads[proto]);
	if (WARN_ON(!ops || !ops->callbacks.gro_complete))
		goto out;

	/* Only need to add sizeof(*iph) to get to the next hdr below
	 * because any hdr with option will have been flushed in
	 * inet_gro_receive().
	 */
	err = INDIRECT_CALL_2(ops->callbacks.gro_complete,
			      tcp4_gro_complete, udp4_gro_complete,
			      skb, nhoff + sizeof(*iph)); // [[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp4_gro_complete().md|tcp4_gro_complete()]]

out:
	return err;
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp4_gro_complete().md|tcp4_gro_complete()]]

> 다시 tcp와 udp로 콜백을 하는 함수이다. 위의 inet_gro_receive()와 그 결이 비슷하다고 볼 수 있다.