---
Parameter:
  - net
  - sock
  - sk_buff
  - net_device
  - sk_buff_
Return: int
Location: /net/ipv4/ip_input.c
---

```c title=ip_rcv_finish_core코드
static int ip_rcv_finish_core(struct net *net, struct sock *sk,
					struct sk_buff *skb, struct net_device *dev,
					const struct sk_buff *hint)
{
	const struct iphdr *iph = ip_hdr(skb);
	int err, drop_reason;
	struct rtable *rt;
	  
	drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
	  
	if (ip_can_use_hint(skb, iph, hint)) {
		err = ip_route_use_hint(skb, iph->daddr, iph->saddr, iph->tos,
					dev, hint);
		if (unlikely(err))
			goto drop_error;
	}
	  
	if (READ_ONCE(net->ipv4.sysctl_ip_early_demux) &&
		!skb_dst(skb) &&
		!skb->sk &&
		!ip_is_fragment(iph)) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
			if (READ_ONCE(net->ipv4.sysctl_tcp_early_demux)) {
				tcp_v4_early_demux(skb);
				  
				/* must reload iph, skb->head might have changed */
				iph = ip_hdr(skb);
			}
			break;
		case IPPROTO_UDP:
			if (READ_ONCE(net->ipv4.sysctl_udp_early_demux)) {
				err = udp_v4_early_demux(skb);
				if (unlikely(err))
					goto drop_error;
				  
				/* must reload iph, skb->head might have changed */
				iph = ip_hdr(skb);
			}
			break;
		}
	}
  
	/*
	* Initialise the virtual path cache for the packet. It describes
	* how the packet travels inside Linux networking.
	*/
	if (!skb_valid_dst(skb)) {
		err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
						iph->tos, dev);
		if (unlikely(err))
			goto drop_error;
	} else {
		struct in_device *in_dev = __in_dev_get_rcu(dev);
		  
		if (in_dev && IN_DEV_ORCONF(in_dev, NOPOLICY))
			IPCB(skb)->flags |= IPSKB_NOPOLICY;
	}
	  
#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif
  
	if (iph->ihl > 5 && ip_rcv_options(skb, dev))
		goto drop;
	  
	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
	} else if (skb->pkt_type == PACKET_BROADCAST ||
			skb->pkt_type == PACKET_MULTICAST) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);
	  
		/* RFC 1122 3.3.6:
		*
		* When a host sends a datagram to a link-layer broadcast
		* address, the IP destination address MUST be a legal IP
		* broadcast or IP multicast address.
		*
		* A host SHOULD silently discard a datagram that is received
		* via a link-layer broadcast (see Section 2.4) but does not
		* specify an IP multicast or broadcast destination address.
		*
		* This doesn't explicitly say L2 *broadcast*, but broadcast is
		* in a way a form of multicast and the most common use case for
		* this is 802.11 protecting against cross-station spoofing (the
		* so-called "hole-196" attack) so do it for both.
		*/
		if (in_dev &&
			IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST)) {
			drop_reason = SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST;
			goto drop;
		}
	}
	  
	return NET_RX_SUCCESS;
	  
drop:
	kfree_skb_reason(skb, drop_reason);
	return NET_RX_DROP;
  
drop_error:
	if (err == -EXDEV) {
		drop_reason = SKB_DROP_REASON_IP_RPFILTER;
		__NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
	}
	goto drop;
}
```

>우선 ip 헤더를 가져온다. 
>현재 경로에서는 `hint` 가 `NULL`값이므로 첫 번째 `if`문은 넘어가야 할 것이다. 
>
>그 다음으로는 `early_demux`가 설정되어 있을 경우, tcp냐 udp냐에 따라서 `switch`문으로 분기하여 해당함수를 호출하게 된다. 여기서 `early_demux`란 말 그대로 더 일찍 demultiplexing을 하는 것이다. tcp 레이어에서 더 일찍 디멀티플렉싱을 하는 것은 포트 번호를 통한 분배 밖에 없을 것이다. 즉, 소켓을 받아와서 모두 만족 할 경우 빠르게 작업을 수행하게 된다.

[[tcp_v4_early_demux()]]
[[ip_route_input_noref()]]
