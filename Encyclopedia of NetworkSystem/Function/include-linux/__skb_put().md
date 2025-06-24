---
Parameter:
  - sk_buff
  - int
Return: void
Location: /include/linux/skbuff.h
---

```c title=__skb_put()
static inline void *__skb_put(struct sk_buff *skb, unsigned int len)
{
	void *tmp = skb_tail_pointer(skb);
	SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;
	return tmp;
}
```

> 통째로 집어 넣는 코드. 좀더 찾아봐야함.