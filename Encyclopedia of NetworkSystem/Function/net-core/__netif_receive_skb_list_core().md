---
Parameter:
  - bool
  - list_head
Return: void
Location: /net/core/dev.c
---

```c title=__netif_receive_skb_list_core()
    static void __netif_receive_skb_list_core(struct list_head *head, bool pfmemalloc)
    {
    	/* Fast-path assumptions:
    	 * - There is no RX handler.
    	 * - Only one packet_type matches.
    	 * If either of these fails, we will end up doing some per-packet
    	 * processing in-line, then handling the 'last ptype' for the whole
    	 * sublist.  This can't cause out-of-order delivery to any single ptype,
    	 * because the 'last ptype' must be constant across the sublist, and all
    	 * other ptypes are handled per-packet.
    	 */
    	/* Current (common) ptype of sublist */
    	struct packet_type *pt_curr = NULL;
    	/* Current (common) orig_dev of sublist */
    	struct net_device *od_curr = NULL;
    	struct list_head sublist;
    	struct sk_buff *skb, *next;
    
    	INIT_LIST_HEAD(&sublist);
    	list_for_each_entry_safe(skb, next, head, list) {
    		struct net_device *orig_dev = skb->dev;
    		struct packet_type *pt_prev = NULL;
    
    		skb_list_del_init(skb); // 원래 list에서 제거 
			// skb 하나씩 꺼내서 → L3 protocol에 맞는 handler 찾고자 호출
			// packet type handler가 pt_prev에 저장됨
    		__netif_receive_skb_core(&skb, pfmemalloc, &pt_prev);
    		// [[Encyclopedia of NetworkSystem/Function/net-core/__netif_receive_skb_core().md|__netif_receive_skb_core()]]
    		if (!pt_prev)
    			continue;
    		if (pt_curr != pt_prev || od_curr != orig_dev) {
    			/* dispatch old sublist */
    			__netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
    			/* start new sublist */
    			INIT_LIST_HEAD(&sublist);
    			pt_curr = pt_prev;
    			od_curr = orig_dev;
    		}
    		list_add_tail(&skb->list, &sublist);
    	}
    
    	/* dispatch final sublist */
    	__netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
    }
```

[[Encyclopedia of NetworkSystem/Function/net-core/__netif_receive_skb_core().md|__netif_receive_skb_core()]]

> head 리스트에 있는 각각의 skb 패킷을 순회하게 되고, 이를 처리하기 위해 `__netif_receive_skb_core()`함수를 호출하게 된다.

---
`__netif_receive_skb_list_core()`는 여러 skb를 모아 놓은 list를 받아서 같은 packet type, orig_dev인 skb만 sublist로 묶고 한 번에 dispatch 한다. 

```c
		list_for_each_entry_safe(skb, next, head, list) {
    		struct net_device *orig_dev = skb->dev;
    		struct packet_type *pt_prev = NULL;
    
    		skb_list_del_init(skb); // 원래 list에서 제거 
    		__netif_receive_skb_core(&skb, pfmemalloc, &pt_prev); 
    		// [[Encyclopedia of NetworkSystem/Function/net-core/__netif_receive_skb_core().md|__netif_receive_skb_core()]] 
    		// packet type handler가 pt_prev에 저장됨
    		
    		if (!pt_prev)
    			continue;

			// packet type(pt_curr) 혹은 device(od_curr)이 바뀌었다면
    		if (pt_curr != pt_prev || od_curr != orig_dev) { 
    			/* dispatch old sublist */
    			// 지금까지의 sublist 전달
    			__netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
    			// 새로운 sublist 생성 후 pt_curr, od_curr을 지금 걸로 초기화
    			INIT_LIST_HEAD(&sublist);
    			pt_curr = pt_prev;
    			od_curr = orig_dev;
    		}
    		// sublist에 추가 
    		list_add_tail(&skb->list, &sublist);
    	}
```

