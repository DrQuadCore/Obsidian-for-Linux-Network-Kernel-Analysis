---
Parameter:
  - list_head
  - sk_buff
Return: void
Location: /net/core/gro.c
---

```c title=gro_list_prepare()
static void gro_list_prepare(const struct list_head *head, const struct sk_buff *skb)
{
    unsigned int maclen = skb->dev->hard_header_len;
    u32 hash = skb_get_hash_raw(skb);
    struct sk_buff *p;
    
    list_for_each_entry(p, head, list) {
    	unsigned long diffs;
    
    	NAPI_GRO_CB(p)->flush = 0;
    
    	if (hash != skb_get_hash_raw(p)) {
    		NAPI_GRO_CB(p)->same_flow = 0;
    		continue;
    	} // hash 값이 다르면 same_flow가 아니라고 판단하고 나간다. 
    		
    	// hash 값이 같은 경우: diff 값에 따라 pkt의 same_flow 값을 정한다. 
    	// diff 변수의 값을 통해 same_flow인지 결정한다.
    	// skb->dev, vlan_all, metadata, mac header가 모두 동일해야 한다. 
    	diffs = (unsigned long)p->dev ^ (unsigned long)skb->dev;
    	diffs |= p->vlan_all ^ skb->vlan_all;
    	diffs |= skb_metadata_differs(p, skb);
    	if (maclen == ETH_HLEN)
    		diffs |= compare_ether_header(skb_mac_header(p),
    					      skb_mac_header(skb));
    	else if (!diffs)
    		diffs = memcmp(skb_mac_header(p),
    			       skb_mac_header(skb),
    			       maclen);
    
    	/* in most common scenarions 'slow_gro' is 0
    	 * otherwise we are already on some slower paths
    	 * either skip all the infrequent tests altogether or
    	 * avoid trying too hard to skip each of them individually
    	 */
    	if (!diffs && unlikely(skb->slow_gro | p->slow_gro)) {
    		diffs |= p->sk != skb->sk;
    		diffs |= skb_metadata_dst_cmp(p, skb);
    		diffs |= skb_get_nfct(p) ^ skb_get_nfct(skb);
    
    		diffs |= gro_list_prepare_tc_ext(skb, p, diffs);
    	}
    
    	NAPI_GRO_CB(p)->same_flow = !diffs;
    	// or 연산한 값들 중 하나라도 다른 것이 있으면, !diff에서 0이 되므로 same_flow가 아닌 것으로 처리 된다. 
    }
}
```

> 리스트의 각각의 entry에 대하여 skb와 헤더, 즉 메타데이터 등을 비교함으로써 같은 flow인지 확인하는 과정을 거친다. 주로 XOR 함수를 통해 그 결과를 diff에 저장하여, 만약 다르다면 1, 같다면 0이 저장 될 것이다. 이를 다시 각각의 skb에 same_flow에 !diff로 저장하게 된다.