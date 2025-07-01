---
Parameter:
  - list_head
Return: void
Location: /net/core/dev.c
---

```c title=dev_gro_receive()
    static enum gro_result dev_gro_receive(struct napi_struct *napi, struct sk_buff *skb) // [[Encyclopedia of NetworkSystem/Struct/include-linux/gro_result.md|gro_result]] [[Encyclopedia of NetworkSystem/Struct/include-linux/sk_buff.md|skbuff]]
    {
    	// 변수 선언 및 초기화
    	u32 bucket = skb_get_hash_raw(skb) & (GRO_HASH_BUCKETS - 1); // 나머지 계산
    	struct gro_list *gro_list = &napi->gro_hash[bucket];
    	struct list_head *head = &net_hotdata.offload_base;
    	struct packet_offload *ptype; // [[Encyclopedia of NetworkSystem/Struct/include-linux/packet_offload.md|packet_offload]]
    	__be16 type = skb->protocol;
    	struct sk_buff *pp = NULL;
    	enum gro_result ret;
    	int same_flow;
    	
    	// GRO 비활성화 조건 확인
    	if (netif_elide_gro(skb->dev)) // [[Encyclopedia of NetworkSystem/Function/include-linux/netif_elide_gro().md|netif_elide_gro()]]
    		goto normal;
    
    	// GRO 리스트 준비
    	gro_list_prepare(&gro_list->list, skb); // [[Encyclopedia of NetworkSystem/Function/net-core/gro_list_prepare().md|gro_list_prepare()]]
    	// gro list 안에 있는 skb 속 control block안에 있는 same flow 변수들을 설정해준다
    	
    	// RCU(Read-Copy-Update) 읽기 잠금
    	rcu_read_lock();
    	list_for_each_entry_rcu(ptype, head, list) {
    		if (ptype->type == type && ptype->callbacks.gro_receive)
    		// list에 있는 pkt들의 protocol이 입력받은 skb와 동일한지 + gro_receive 인지 확인
    			goto found_ptype;
    	}
    	rcu_read_unlock();
    	goto normal;
    
    found_ptype:
    	// 패킷 헤더 설정
    	skb_set_network_header(skb, skb_gro_offset(skb));
    	skb_reset_mac_len(skb);
    	BUILD_BUG_ON(sizeof_field(struct napi_gro_cb, zeroed) != sizeof(u32));
    	BUILD_BUG_ON(!IS_ALIGNED(offsetof(struct napi_gro_cb, zeroed),
    					sizeof(u32))); /* Avoid slow unaligned acc */
    	*(u32 *)&NAPI_GRO_CB(skb)->zeroed = 0;
    	NAPI_GRO_CB(skb)->flush = skb_has_frag_list(skb); // [[Encyclopedia of NetworkSystem/Struct/include-net/napi_gro_cb.md|NAPI_GRO_CB]]
    	NAPI_GRO_CB(skb)->is_atomic = 1;
    	NAPI_GRO_CB(skb)->count = 1;
    	if (unlikely(skb_is_gso(skb))) {
    		NAPI_GRO_CB(skb)->count = skb_shinfo(skb)->gso_segs;
    		// gso로 생성된 skb의 경우, count 변수에 gso_segment 개수를 설정해준다. 
    		/* Only support TCP and non DODGY users. */
    		if (!skb_is_gso_tcp(skb) ||
    		    (skb_shinfo(skb)->gso_type & SKB_GSO_DODGY))
    			NAPI_GRO_CB(skb)->flush = 1;
    	}
    
    	/* Setup for GRO checksum validation */
    	// GRO 체크섬 검증 설정
    	switch (skb->ip_summed) {
    	case CHECKSUM_COMPLETE:
    		NAPI_GRO_CB(skb)->csum = skb->csum;
    		NAPI_GRO_CB(skb)->csum_valid = 1;
    		break;
    	case CHECKSUM_UNNECESSARY:
    		NAPI_GRO_CB(skb)->csum_cnt = skb->csum_level + 1;
    		break;
    	}
    	
    	// 패킷 처리
    	pp = INDIRECT_CALL_INET(ptype->callbacks.gro_receive,
    				ipv6_gro_receive, inet_gro_receive,
    				&gro_list->list, skb); // [[Encyclopedia of NetworkSystem/Function/net-ipv6/ipv6_gro_receive().md|ipv6_gro_receive()]] [[Encyclopedia of NetworkSystem/Function/net-ipv4/inet_gro_receive().md|inet_gro_receive()]] 
    
    	rcu_read_unlock();
    
    	if (PTR_ERR(pp) == -EINPROGRESS) {
    		ret = GRO_CONSUMED;
    		goto ok;
    	}
    
    	same_flow = NAPI_GRO_CB(skb)->same_flow;
    	ret = NAPI_GRO_CB(skb)->free ? GRO_MERGED_FREE : GRO_MERGED;
    
    	if (pp) {
    		skb_list_del_init(pp);
	    	napi_gro_complete(napi, pp); // [[Encyclopedia of NetworkSystem/Function/net-core/napi_gro_complete().md|napi_gro_complete()]]
    		gro_list->count--;
    	}
    
    	if (same_flow)
    		goto ok;
    
    	if (NAPI_GRO_CB(skb)->flush)
    		goto normal;
    
    	if (unlikely(gro_list->count >= MAX_GRO_SKBS))
    		gro_flush_oldest(napi, &gro_list->list);
    	else
    		gro_list->count++;
    
    	/* Must be called before setting NAPI_GRO_CB(skb)->{age|last} */
    	gro_try_pull_from_frag0(skb);
    	NAPI_GRO_CB(skb)->age = jiffies;
    	NAPI_GRO_CB(skb)->last = skb;
    	if (!skb_is_gso(skb))
    		skb_shinfo(skb)->gso_size = skb_gro_len(skb);
    	list_add(&skb->list, &gro_list->list);
    	ret = GRO_HELD;
    ok:
    	if (gro_list->count) {
    		if (!test_bit(bucket, &napi->gro_bitmask))
    			__set_bit(bucket, &napi->gro_bitmask);
    	} else if (test_bit(bucket, &napi->gro_bitmask)) {
    		__clear_bit(bucket, &napi->gro_bitmask);
    	}
    
    	return ret;
    
    normal:
    	ret = GRO_NORMAL;
    	gro_try_pull_from_frag0(skb);
    	goto ok;
    }
```

[[Encyclopedia of NetworkSystem/Struct/include-linux/gro_result.md|gro_result]] 
[[Encyclopedia of NetworkSystem/Struct/include-linux/sk_buff.md|skbuff]]
[[Encyclopedia of NetworkSystem/Struct/include-linux/packet_offload.md|packet_offload]]
[[Encyclopedia of NetworkSystem/Function/include-linux/netif_elide_gro().md|netif_elide_gro()]]
[[Encyclopedia of NetworkSystem/Function/net-core/gro_list_prepare().md|gro_list_prepare()]]
[[Encyclopedia of NetworkSystem/Struct/include-net/napi_gro_cb.md|NAPI_GRO_CB]]
[[Encyclopedia of NetworkSystem/Function/net-ipv6/ipv6_gro_receive().md|ipv6_gro_receive()]]
[[Encyclopedia of NetworkSystem/Function/net-ipv4/inet_gro_receive().md|inet_gro_receive()]]
[[Encyclopedia of NetworkSystem/Function/net-core/napi_gro_complete().md|napi_gro_complete()]]

> 실질적으로 gro를 처리하는 함수. 인수로 받아온 skb 포인터에다가 패킷 정보를 쌓기 시작함. 코드 중간에 pp = `INDIRECT_CALL_INET()`이라는 함수가 호출되는데 여기서 IPv4와 IPv6로 나뉘어 콜백이 되게 됨. gro_list도 함께 전달해주며, 이는` &napi→gro_hash[bucket]`에서 가져온 결과임. 더 깊은 호출은 net/ipv4/af_inet.c의 `inet_gro_receive()` 함수를 보면 됨.

>만약 합친 `return`이 있다면(패킷 병합이 이루어짐. 아니라면 `NULL`반환, -> `tcp_gro_receive()`함수에서 보면 `pp`는 `NULL`로 initialize 됨) 따라서 `if(pp)`라면, 여기서 `gro_list->count--`를 하는 이유는 `skb_list_del_init(pp)` 를 통해 `gro_list`에서 해당 패킷을 dequeue하기 때문이다. 더이상 `napi->gro_hash` array에 있지 않기 때문에 이를 위해서 `gro_list->count--`를 하게 되는 것이다.
>
>만약 합쳐진거라면 `same_flow`가 `true`이므로 바로 `ok`라벨로 가게 된다. 만약 아니라면, 새로 `gro_list`에 추가되어야 하므로 우선 `gro_list`가 가득 찼다면 오래된 패킷을 드랍한다. 아니면 `list_add()`함수를 통해 해당 패킷을 추가하게 된다.


1. **해시 계산 및 리스트 설정**:
   - 패킷의 해시 값을 계산하여 적절한 gro_list를 선택한다.
   - gro_list_prepare로 리스트를 준비한다.
2. **GRO 비활성화 조건 확인**:
   - netif_elide_gro를 사용해 GRO를 비활성화할지 결정한다.
3. **패킷 타입 확인 및 처리**:
   - rcu_read_lock을 사용해 RCU 읽기 잠금을 설정하고, packet_offload 리스트를 통해 패킷 타입을 확인한다.
   - 해당 타입을 찾으면 해당 콜백 함수를 호출하여 패킷을 처리한다.
4. **패킷 헤더 및 체크섬 설정**:
   - 패킷의 네트워크 헤더와 MAC 길이를 설정하고, 체크섬 검증을 설정한다.
5. **GRO 수신 처리**:
   - ptype->callbacks.gro_receive 함수를 호출하여 패킷을 처리한다.
   - 패킷이 동일한 흐름인지 확인하고, 병합 결과에 따라 적절한 처리를 수행한다.
6. **패킷 리스트 관리**:
   - 병합된 패킷 리스트를 관리하고, 필요시 오래된 패킷을 플러시한다.
   - 새로운 패킷을 리스트에 추가하고, 타이머를 설정한다.
7. **결과 반환**:
   - 최종적으로 처리 결과를 반환한다.