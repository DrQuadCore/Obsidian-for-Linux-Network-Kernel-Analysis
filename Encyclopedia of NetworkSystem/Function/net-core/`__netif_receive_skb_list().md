```c
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
	/* Restore pflags */
	if (pfmemalloc)
		memalloc_noreclaim_restore(noreclaim_flag);
}
```
