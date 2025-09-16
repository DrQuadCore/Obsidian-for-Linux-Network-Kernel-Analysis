---
Parameter:
- sk_buff_head *
- sk_buff *
Return:
- void
Location:
- /include/linux/skbuff.h
---

```c title=__skb_queue_tail()
/**
 *	__skb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the end of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
static inline void __skb_queue_tail(struct sk_buff_head *list,
				   struct sk_buff *newsk)
{
	__skb_queue_before(list, (struct sk_buff *)list, newsk);
}
```

```c title=__skb_queue_before()
static inline void __skb_queue_before(struct sk_buff_head *list,
				      struct sk_buff *next,
				      struct sk_buff *newsk)
{
	__skb_insert(newsk, ((struct sk_buff_list *)next)->prev, next, list);
}
```
`list`는 큐의 헤더 노드이므로 `list`의 다음 노드(원래 맨끝 노드) 뒤에 새 노드(`newsk`)를 삽입하게 한다. 즉, 큐의 끝에 `newsk`를 삽입한다.

```c title=__skb_insert()
/*
 *	Insert an sk_buff on a list.
 *
 *	The "__skb_xxxx()" functions are the non-atomic ones that
 *	can only be called with interrupts disabled.
 */
static inline void __skb_insert(struct sk_buff *newsk,
				struct sk_buff *prev, struct sk_buff *next,
				struct sk_buff_head *list)
{
	/* See skb_queue_empty_lockless() and skb_peek_tail()
	 * for the opposite READ_ONCE()
	 */
	WRITE_ONCE(newsk->next, next);
	WRITE_ONCE(newsk->prev, prev);
	WRITE_ONCE(((struct sk_buff_list *)next)->prev, newsk);
	WRITE_ONCE(((struct sk_buff_list *)prev)->next, newsk);
	WRITE_ONCE(list->qlen, list->qlen + 1);
}
```
 