---
Parameter:
  - bool
  - packet_type
  - sk_buff
Return: int
Location: /net/core/dev.c
---

```c title=__netif_receive_skb_core()
    static int __netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc, struct packet_type **ppt_prev)
    {
    	struct packet_type *ptype, *pt_prev;
    	rx_handler_func_t *rx_handler;
    	struct sk_buff *skb = *pskb;
    	struct net_device *orig_dev;
    	bool deliver_exact = false;
    	int ret = NET_RX_DROP;
    	__be16 type;
    
    	net_timestamp_check(!READ_ONCE(net_hotdata.tstamp_prequeue), skb);
    
    	trace_netif_receive_skb(skb);
    
    	orig_dev = skb->dev;
    
    	skb_reset_network_header(skb);
    	if (!skb_transport_header_was_set(skb))
    		skb_reset_transport_header(skb);
    	skb_reset_mac_len(skb);
    
    	pt_prev = NULL;
    
    another_round:
    	skb->skb_iif = skb->dev->ifindex;
    
    	__this_cpu_inc(softnet_data.processed);
    
    	if (static_branch_unlikely(&generic_xdp_needed_key)) {
    		int ret2;
    
    		migrate_disable();
    		ret2 = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog),
    				      &skb);
    		migrate_enable();
    
    		if (ret2 != XDP_PASS) {
    			ret = NET_RX_DROP;
    			goto out;
    		}
    	}
    
    	if (eth_type_vlan(skb->protocol)) {
    		skb = skb_vlan_untag(skb);
    		if (unlikely(!skb))
    			goto out;
    	}
    
    	if (skb_skip_tc_classify(skb))
    		goto skip_classify;
    
    	if (pfmemalloc)
    		goto skip_taps;
    
    	list_for_each_entry_rcu(ptype, &net_hotdata.ptype_all, list) {
    		if (pt_prev)
    			ret = deliver_skb(skb, pt_prev, orig_dev); // [[Encyclopedia of NetworkSystem/Function/net-core/deliver_skb().md|deliver_skb()]]
    		pt_prev = ptype;
    	}
    
    	list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list) {
    		if (pt_prev)
    			ret = deliver_skb(skb, pt_prev, orig_dev); // [[Encyclopedia of NetworkSystem/Function/net-core/deliver_skb().md|deliver_skb()]]
    		pt_prev = ptype;
    	}
    
    skip_taps:
    #ifdef CONFIG_NET_INGRESS
    	if (static_branch_unlikely(&ingress_needed_key)) {
    		bool another = false;
    
    		nf_skip_egress(skb, true);
    		skb = sch_handle_ingress(skb, &pt_prev, &ret, orig_dev,
    					 &another);
    		if (another)
    			goto another_round;
    		if (!skb)
    			goto out;
    
    		nf_skip_egress(skb, false);
    		if (nf_ingress(skb, &pt_prev, &ret, orig_dev) < 0)
    			goto out;
    	}
    #endif
    	skb_reset_redirect(skb);
    skip_classify:
    	if (pfmemalloc && !skb_pfmemalloc_protocol(skb))
    		goto drop;
    
    	if (skb_vlan_tag_present(skb)) {
    		if (pt_prev) {
    			ret = deliver_skb(skb, pt_prev, orig_dev); // [[Encyclopedia of NetworkSystem/Function/net-core/deliver_skb().md|deliver_skb()]]
    			pt_prev = NULL;
    		}
    		if (vlan_do_receive(&skb))
    			goto another_round;
    		else if (unlikely(!skb))
    			goto out;
    	}
    
    	rx_handler = rcu_dereference(skb->dev->rx_handler);
    	if (rx_handler) {
    		if (pt_prev) {
    			ret = deliver_skb(skb, pt_prev, orig_dev); // [[Encyclopedia of NetworkSystem/Function/net-core/deliver_skb().md|deliver_skb()]]
    			pt_prev = NULL;
    		}
    		switch (rx_handler(&skb)) {
    		case RX_HANDLER_CONSUMED:
    			ret = NET_RX_SUCCESS;
    			goto out;
    		case RX_HANDLER_ANOTHER:
    			goto another_round;
    		case RX_HANDLER_EXACT:
    			deliver_exact = true;
    			break;
    		case RX_HANDLER_PASS:
    			break;
    		default:
    			BUG();
    		}
    	}
    
    	if (unlikely(skb_vlan_tag_present(skb)) && !netdev_uses_dsa(skb->dev)) {
    check_vlan_id:
    		if (skb_vlan_tag_get_id(skb)) {
    			/* Vlan id is non 0 and vlan_do_receive() above couldn't
    			 * find vlan device.
    			 */
    			skb->pkt_type = PACKET_OTHERHOST;
    		} else if (eth_type_vlan(skb->protocol)) {
    			/* Outer header is 802.1P with vlan 0, inner header is
    			 * 802.1Q or 802.1AD and vlan_do_receive() above could
    			 * not find vlan dev for vlan id 0.
    			 */
    			__vlan_hwaccel_clear_tag(skb);
    			skb = skb_vlan_untag(skb);
    			if (unlikely(!skb))
    				goto out;
    			if (vlan_do_receive(&skb))
    				/* After stripping off 802.1P header with vlan 0
    				 * vlan dev is found for inner header.
    				 */
    				goto another_round;
    			else if (unlikely(!skb))
    				goto out;
    			else
    				/* We have stripped outer 802.1P vlan 0 header.
    				 * But could not find vlan dev.
    				 * check again for vlan id to set OTHERHOST.
    				 */
    				goto check_vlan_id;
    		}
    		/* Note: we might in the future use prio bits
    		 * and set skb->priority like in vlan_do_receive()
    		 * For the time being, just ignore Priority Code Point
    		 */
    		__vlan_hwaccel_clear_tag(skb);
    	}
    
    	type = skb->protocol;
    
    	/* deliver only exact match when indicated */
    	if (likely(!deliver_exact)) {
    		deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
    				       &ptype_base[ntohs(type) &
    						   PTYPE_HASH_MASK]);
    	}
    
    	deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
    			       &orig_dev->ptype_specific);
    
    	if (unlikely(skb->dev != orig_dev)) {
    		deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
    				       &skb->dev->ptype_specific);
    	}
    
    	if (pt_prev) {
    		if (unlikely(skb_orphan_frags_rx(skb, GFP_ATOMIC)))
    			goto drop;
    		*ppt_prev = pt_prev;
    	} else {
    drop:
    		if (!deliver_exact)
    			dev_core_stats_rx_dropped_inc(skb->dev);
    		else
    			dev_core_stats_rx_nohandler_inc(skb->dev);
    		kfree_skb_reason(skb, SKB_DROP_REASON_UNHANDLED_PROTO);
    		/* Jamal, now you will not able to escape explaining
    		 * me how you were going to use this. :-)
    		 */
    		ret = NET_RX_DROP;
    	}
    
    out:
    	/* The invariant here is that if *ppt_prev is not NULL
    	 * then skb should also be non-NULL.
    	 *
    	 * Apparently *ppt_prev assignment above holds this invariant due to
    	 * skb dereferencing near it.
    	 */
    	*pskb = skb;
    	return ret;
    }
```

[[Encyclopedia of NetworkSystem/Function/net-core/deliver_skb().md|deliver_skb()]]

> 각종 체크를 통해 패킷을 드랍하거나 스택을 올려보내는 처리를 수행한다. 중간에 모든 entry에 대하여 deliver_skb() 함수를 호출해서 스택 위로 올려보내는 역할을 수행하게 된다.