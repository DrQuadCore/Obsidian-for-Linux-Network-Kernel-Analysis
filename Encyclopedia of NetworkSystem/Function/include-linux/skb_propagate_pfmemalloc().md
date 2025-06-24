---
Parameter:
  - page
  - sk_buff
Return: void
Location: /include/linux/skbuff.h
---

```c title=netif_tx_start_all_queues()
/**
 *	skb_propagate_pfmemalloc - Propagate pfmemalloc if skb is allocated after RX page
 *	@page: The page that was allocated from skb_alloc_page
 *	@skb: The skb that may need pfmemalloc set
 */
static inline void skb_propagate_pfmemalloc(const struct page *page,
					    struct sk_buff *skb)
{
	if (page_is_pfmemalloc(page))
		skb->pfmemalloc = true;
}
```
