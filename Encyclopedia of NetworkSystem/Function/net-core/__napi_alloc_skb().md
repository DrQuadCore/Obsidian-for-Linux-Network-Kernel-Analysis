---
Parameter:
  - gfp_t
  - int
  - napi_struct
Return: sk_buff
Location: /net/core/skbuff.c
---

```c title=__napi_alloc_skb()
	/**
     *	__napi_alloc_skb - allocate skbuff for rx in a specific NAPI instance
     *	@napi: napi instance this buffer was allocated for
     *	@len: length to allocate
     *	@gfp_mask: get_free_pages mask, passed to alloc_skb and alloc_pages
     *
     *	Allocate a new sk_buff for use in NAPI receive.  This buffer will
     *	attempt to allocate the head from a special reserved region used
     *	only for NAPI Rx allocation.  By doing this we can save several
     *	CPU cycles by avoiding having to disable and re-enable IRQs.
     *
     *	%NULL is returned if there is no free memory.
     */
    struct sk_buff *__napi_alloc_skb(struct napi_struct *napi, unsigned int len,
    				 gfp_t gfp_mask)
    {
    	struct napi_alloc_cache *nc;
    	struct sk_buff *skb;
    	bool pfmemalloc;
    	void *data;
    
    	DEBUG_NET_WARN_ON_ONCE(!in_softirq());
    	len += NET_SKB_PAD + NET_IP_ALIGN;
    
    	/* If requested length is either too small or too big,
    	 * we use kmalloc() for skb->head allocation.
    	 * When the small frag allocator is available, prefer it over kmalloc
    	 * for small fragments
    	 */
    	if ((!NAPI_HAS_SMALL_PAGE_FRAG && len <= SKB_WITH_OVERHEAD(1024)) ||
    	    len > SKB_WITH_OVERHEAD(PAGE_SIZE) ||
    	    (gfp_mask & (__GFP_DIRECT_RECLAIM | GFP_DMA))) {
    		skb = __alloc_skb(len, gfp_mask, SKB_ALLOC_RX | SKB_ALLOC_NAPI,
    				  NUMA_NO_NODE); // [[Encyclopedia of NetworkSystem/Function/net-core/__alloc_skb().md|__alloc_skb()]]
    		if (!skb)
    			goto skb_fail;
    		goto skb_success;
    	}
    
    	nc = this_cpu_ptr(&napi_alloc_cache);
    
    	if (sk_memalloc_socks())
    		gfp_mask |= __GFP_MEMALLOC;
    
    	if (NAPI_HAS_SMALL_PAGE_FRAG && len <= SKB_WITH_OVERHEAD(1024)) {
    		/* we are artificially inflating the allocation size, but
    		 * that is not as bad as it may look like, as:
    		 * - 'len' less than GRO_MAX_HEAD makes little sense
    		 * - On most systems, larger 'len' values lead to fragment
    		 *   size above 512 bytes
    		 * - kmalloc would use the kmalloc-1k slab for such values
    		 * - Builds with smaller GRO_MAX_HEAD will very likely do
    		 *   little networking, as that implies no WiFi and no
    		 *   tunnels support, and 32 bits arches.
    		 */
    		len = SZ_1K;
    
    		data = page_frag_alloc_1k(&nc->page_small, gfp_mask);
    		pfmemalloc = NAPI_SMALL_PAGE_PFMEMALLOC(nc->page_small);
    	} else {
    		len = SKB_HEAD_ALIGN(len);
    
    		data = page_frag_alloc(&nc->page, len, gfp_mask);
    		pfmemalloc = nc->page.pfmemalloc;
    	}
    
    	if (unlikely(!data))
    		return NULL;
    
    	skb = __napi_build_skb(data, len);
    	if (unlikely(!skb)) {
    		skb_free_frag(data);
    		return NULL;
    	}
    
    	if (pfmemalloc)
    		skb->pfmemalloc = 1;
    	skb->head_frag = 1;
    
    skb_success:
    	skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);
    	skb->dev = napi->dev;
    
    skb_fail:
    	return skb;
    }
    EXPORT_SYMBOL(__napi_alloc_skb);
```

[[Encyclopedia of NetworkSystem/Function/net-core/__alloc_skb().md|__alloc_skb()]]

> 만약 별 문제가 없다면 `__alloc_skb()`를 통해 skb를 새로 할당하게 되고, 이후의 과정은 `__napi_build_skb`등을 거치며 위의 ice_build_skb와 같아지게 된다. 즉, 사용할 skb가 할당 되어있는지 여부에 의해 사용될 함수가 결정된다고 볼 수 있다.
