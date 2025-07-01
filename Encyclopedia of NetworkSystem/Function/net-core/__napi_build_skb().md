---
Parameter:
  - int
  - void
Return: sk_buff
Location: /net/core/skbuff.c
---

```c title=__napi_build_skb()
    /**
	 * __napi_build_skb - build a network buffer
	 * @data: data buffer provided by caller
	 * @frag_size: size of data
	 *
	 * Version of __build_skb() that uses NAPI percpu caches to obtain
	 * skbuff_head instead of inplace allocation.
	 *
	 * Returns a new &sk_buff on success, %NULL on allocation failure.
	 */
static struct sk_buff *__napi_build_skb(void *data, unsigned int frag_size)
{
	struct sk_buff *skb;

	skb = napi_skb_cache_get();
	if (unlikely(!skb))
		return NULL;

	memset(skb, 0, offsetof(struct sk_buff, tail));
	__build_skb_around(skb, data, frag_size);

	return skb;
}
```

> 이 함수는 우선 `napi_skb_cache_get()`을 통해 CPU 로컬한 캐시에서 skb_cache를 가져오는 작업을 하게 된다. 이는 성능향상을 위한 작업이며, 이후 skb의 크기만큼 memset을 통해 초기화를 해주고 `__build_skb_around()`를 통해 마저 skb를 구성하게 된다.
