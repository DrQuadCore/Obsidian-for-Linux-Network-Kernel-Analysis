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

---

```c title=sk_buff
@pfmemalloc: skbuff was allocated from PFMEMALLOC reserves
```

pfmemalloc skb는 메모리 부족 상황에서도 반드시 처리해야 하는 네트워크 패킷을 의미한다. 

```c
// head = &napi->rx_list
    	list_for_each_entry_safe(skb, next, head, list) {
    		if ((sk_memalloc_socks() && skb_pfmemalloc(skb)) != pfmemalloc) {
    			struct list_head sublist;
    
    			/* Handle the previous sublist */
    			
    			/**
				 * list_cut_before - cut a list into two, before given entry 
				 * @list: a new list to add all removed entries 
				 * @head: a list with entries 
				 * @entry: an entry within head, could be the head itself
				 */
    			list_cut_before(&sublist, head, &skb->list);
    			
    			if (!list_empty(&sublist))
    				__netif_receive_skb_list_core(&sublist, pfmemalloc);
    				// [[__netif_receive_skb_list_core()]]
    			pfmemalloc = !pfmemalloc;
    			/* See comments in __netif_receive_skb */
    			if (pfmemalloc)
    				noreclaim_flag = memalloc_noreclaim_save();
    			else
    				memalloc_noreclaim_restore(noreclaim_flag);
    		}
    	}
```

모든 skb에 대해, 현재 skb가 PF_MEMALLOC 패킷인지 검사한다. 만약 pfmemalloc 여부가 바뀌면 (이전까진 pfmemalloc이었으나 현재는 아님 or 이전까진 아니었으나 현잰 pfmemalloc임) sublist에 이전까지의 list를 잘라서 붙인다. 이후` __netif_receive_skb_list_core()`에 sublist를 넘긴다.

현재 처리한 packet이 pfmealloc일 경우, `memalloc_noreclaim_save()`를 호출한다. 반환값에는 이전 상태가 저장되며 나중에 restore로 상태를 복원할 수 있다. 

이 함수는 메모리 free 과정에서 일부 메모리를 추가로 할당해야 하지만 recursion이 발생할 수 있으므로 reclaim을  할 수 없는 경우에 사용된다. 예를 들어, 빈 page가 없을 때 dirty page를 disk에 write-out 하고 free를 하려고 할 수 있다. 그러나 write out 대상이 네트워크를 통해 접근하는 device(e.g. Network File System)라면 packet을 전송을 위해 skb를 할당해야 하는데 이 과정에서도 page가 필요하므로 또 다시 free page를 찾아서 allocation을 시도하려고 하는 상황이 발생할 수 있다. 이 함수는 이러한 경우 그냥 reserve 메모리에서 직접 page를 사용하도록 한다. 

```c title=memalloc_noreclaim_save()
/**
 * memalloc_noreclaim_save - Marks implicit __GFP_MEMALLOC scope.
 *
 * This function marks the beginning of the __GFP_MEMALLOC allocation scope.
 * All further allocations will implicitly add the __GFP_MEMALLOC flag, which
 * prevents entering reclaim and allows access to all memory reserves. This
 * should only be used when the caller guarantees the allocation will allow more
 * memory to be freed very shortly, i.e. it needs to allocate some memory in
 * the process of freeing memory, and cannot reclaim due to potential recursion.
 *
 * Users of this scope have to be extremely careful to not deplete the reserves
 * completely and implement a throttling mechanism which controls the
 * consumption of the reserve based on the amount of freed memory. Usage of a
 * pre-allocated pool (e.g. mempool) should be always considered before using
 * this scope.
 *
 * Individual allocations under the scope can opt out using __GFP_NOMEMALLOC
 *
 * Context: This function should not be used in an interrupt context as that one
 *          does not give PF_MEMALLOC access to reserves.
 *          See __gfp_pfmemalloc_flags().
 * Return: The saved flags to be passed to memalloc_noreclaim_restore.
 */
static inline unsigned int memalloc_noreclaim_save(void)
{
	return memalloc_flags_save(PF_MEMALLOC);
}

```