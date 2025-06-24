---
Parameter:
  - gfp_t
  - int
Return: sk_buff
Location: /net/core/skbuff.c
---

```c title=__alloc_skb()
    /* 	Allocate a new skbuff. We do this ourselves so we can fill in a few
     *	'private' fields and also do memory statistics to find all the
     *	[BEEP] leaks.
     *
     */
    
    /**
     *	__alloc_skb	-	allocate a network buffer
     *	@size: size to allocate
     *	@gfp_mask: allocation mask
     *	@flags: If SKB_ALLOC_FCLONE is set, allocate from fclone cache
     *		instead of head cache and allocate a cloned (child) skb.
     *		If SKB_ALLOC_RX is set, __GFP_MEMALLOC will be used for
     *		allocations in case the data is required for writeback
     *	@node: numa node to allocate memory on
     *
     *	Allocate a new &sk_buff. The returned buffer has no headroom and a
     *	tail room of at least size bytes. The object has a reference count
     *	of one. The return is the buffer. On a failure the return is %NULL.
     *
     *	Buffers may only be allocated from interrupts using a @gfp_mask of
     *	%GFP_ATOMIC.
     */
    struct sk_buff *__alloc_skb(unsigned int size, gfp_t gfp_mask,
    			    int flags, int node)
    {
    	struct kmem_cache *cache;
    	struct sk_buff *skb;
    	bool pfmemalloc;
    	u8 *data;
    
    	cache = (flags & SKB_ALLOC_FCLONE)
    		? net_hotdata.skbuff_fclone_cache : net_hotdata.skbuff_cache;
    
    	if (sk_memalloc_socks() && (flags & SKB_ALLOC_RX))
    		gfp_mask |= __GFP_MEMALLOC;
    
    	/* Get the HEAD */
    	if ((flags & (SKB_ALLOC_FCLONE | SKB_ALLOC_NAPI)) == SKB_ALLOC_NAPI &&
    	    likely(node == NUMA_NO_NODE || node == numa_mem_id()))
    		skb = napi_skb_cache_get();
    	else
    		skb = kmem_cache_alloc_node(cache, gfp_mask & ~GFP_DMA, node);
    	if (unlikely(!skb))
    		return NULL;
    	prefetchw(skb);
    
    	/* We do our best to align skb_shared_info on a separate cache
    	 * line. It usually works because kmalloc(X > SMP_CACHE_BYTES) gives
    	 * aligned memory blocks, unless SLUB/SLAB debug is enabled.
    	 * Both skb->head and skb_shared_info are cache line aligned.
    	 */
    	data = kmalloc_reserve(&size, gfp_mask, node, &pfmemalloc);
    	if (unlikely(!data))
    		goto nodata;
    	/* kmalloc_size_roundup() might give us more room than requested.
    	 * Put skb_shared_info exactly at the end of allocated zone,
    	 * to allow max possible filling before reallocation.
    	 */
    	prefetchw(data + SKB_WITH_OVERHEAD(size));
    
    	/*
    	 * Only clear those fields we need to clear, not those that we will
    	 * actually initialise below. Hence, don't put any more fields after
    	 * the tail pointer in struct sk_buff!
    	 */
    	memset(skb, 0, offsetof(struct sk_buff, tail));
    	__build_skb_around(skb, data, size);
    	skb->pfmemalloc = pfmemalloc;
    
    	if (flags & SKB_ALLOC_FCLONE) {
    		struct sk_buff_fclones *fclones;
    
    		fclones = container_of(skb, struct sk_buff_fclones, skb1);
    
    		skb->fclone = SKB_FCLONE_ORIG;
    		refcount_set(&fclones->fclone_ref, 1);
    	}
    
    	return skb;
    
    nodata:
    	kmem_cache_free(cache, skb);
    	return NULL;
    }
    EXPORT_SYMBOL(__alloc_skb);
```

> 새로운 skb를 할당하는 함수. numa local한 캐시에서 sk_buff 할당 받은게 있다면 꺼내오고 아니면 새로 할당하게 된다. 이때, sk_buff는 초기에 CPU마다 대량으로 할당되어 있고, `napi_skb_cache_get()`을 통해 가져다가 쓸 수 있게 된다. 이후 `kmalloc_reserve()`를 호출하여 실제 data를 담을 공간을 할당 받는다.