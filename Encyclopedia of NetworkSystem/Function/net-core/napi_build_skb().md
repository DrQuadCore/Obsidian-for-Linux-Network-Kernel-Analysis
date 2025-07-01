---
Parameter:
  - int
  - void
Return: sk_buff
Location: /net/core/skbuff.c
---

```c title=napi_build_skb()
/**
 * napi_build_skb - build a network buffer
 * @data: data buffer provided by caller
 * @frag_size: size of data
 *
 * Version of __napi_build_skb() that takes care of skb->head_frag
 * and skb->pfmemalloc when the data is a page or page fragment.
 *
 * Returns a new &sk_buff on success, %NULL on allocation failure.
 */
struct sk_buff *napi_build_skb(void *data, unsigned int frag_size)
{
	struct sk_buff *skb = __napi_build_skb(data, frag_size); // [[Encyclopedia of NetworkSystem/Function/net-core/__napi_build_skb().md|__napi_build_skb()]]

	if (likely(skb) && frag_size) {
		skb->head_frag = 1;
		skb_propagate_pfmemalloc(virt_to_head_page(data), skb); // [[Encyclopedia of NetworkSystem/Function/include-linux/skb_propagate_pfmemalloc().md|skb_propagate_pfmemalloc()]]
	}

	return skb;
}
EXPORT_SYMBOL(napi_build_skb);
```

[[Encyclopedia of NetworkSystem/Function/net-core/__napi_build_skb().md|__napi_build_skb()]]
[[Encyclopedia of NetworkSystem/Function/include-linux/skb_propagate_pfmemalloc().md|skb_propagate_pfmemalloc()]]

> `__napi_build_skb`를 실행하여 skb 포인터를 획득하고, 이를 다시 반환한다. 이후 `skb_propagate_pfmemalloc`을 호출하게 된다.