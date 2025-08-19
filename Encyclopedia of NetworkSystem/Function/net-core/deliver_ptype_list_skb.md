---
Parameter:
  - sk_buff
  - packet_type
  - net_device
  - __be16
  - list_head
Return: void
Location: /net/core/dev.c
---
```c title='deliver_ptype_list_skb'
static inline void deliver_ptype_list_skb(struct sk_buff *skb,
					  struct packet_type **pt,
					  struct net_device *orig_dev,
					  __be16 type,
					  struct list_head *ptype_list)
{
	struct packet_type *ptype, *pt_prev = *pt;

	list_for_each_entry_rcu(ptype, ptype_list, list) {
		if (ptype->type != type)
			continue;
		if (pt_prev)
			deliver_skb(skb, pt_prev, orig_dev); // [[deliver_skb()]]
		pt_prev = ptype;
	}
	*pt = pt_prev;
}

```

>찾은 bucket의 ptype_list를 순회하며 ptype->type == type 조건을 만족시키는 핸들러를 찾는다. 핸들러와 skb는 다시 `deliver_skb()` 함수로 전달한다.
