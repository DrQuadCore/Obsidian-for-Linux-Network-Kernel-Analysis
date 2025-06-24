---
Parameter:
  - list_head
Return: void
Location: /net/core/dev.c
---

```c title=__netif_receive_skb_list()
    static void __netif_receive_skb_list(struct list_head *head)
    {
    	unsigned long noreclaim_flag = 0;
    	struct sk_buff *skb, *next;
    	bool pfmemalloc = false; /* Is current sublist PF_MEMALLOC? */
    
    	list_for_each_entry_safe(skb, next, head, list) {
    		if ((sk_memalloc_socks() && skb_pfmemalloc(skb)) != pfmemalloc) {
    			struct list_head sublist;
    
    			/* Handle the previous sublist */
    			list_cut_before(&sublist, head, &skb->list);
    			if (!list_empty(&sublist))
    				__netif_receive_skb_list_core(&sublist, pfmemalloc);
    			pfmemalloc = !pfmemalloc;
    			/* See comments in __netif_receive_skb */
    			if (pfmemalloc)
    				noreclaim_flag = memalloc_noreclaim_save();
    			else
    				memalloc_noreclaim_restore(noreclaim_flag);
    		}
    	}
    	/* Handle the remaining sublist */
    	if (!list_empty(head))
    		__netif_receive_skb_list_core(head, pfmemalloc);
    		// [[Encyclopedia of NetworkSystem/Function/net-core/__netif_receive_skb_list_core().md|__netif_receive_skb_list_core()]]
    	/* Restore pflags */
    	if (pfmemalloc)
    		memalloc_noreclaim_restore(noreclaim_flag);
    }
```

[[Encyclopedia of NetworkSystem/Function/net-core/__netif_receive_skb_list_core().md|__netif_receive_skb_list_core()]]

> 리스트의 각각의 skb에 대하여 pfmemalloc과 관련한 처리를 수행한다. 관련하여 더 찾아보려 하였으나 네트워크 스택과 깊이 관련이 있지 않은 것으로 판단하여 멈추었다. 그후 만약 리스트가 비어있지 않다면 `__netif_receive_skb_list_core()`를 호출하게 된다.