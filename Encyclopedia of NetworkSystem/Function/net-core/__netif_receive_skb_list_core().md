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
    
    		skb_list_del_init(skb);
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