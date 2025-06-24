---
Parameter:
  - list_head
Return: void
Location: /include/linux/list.h
---

```c title=list_add_tail()
/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}
```

list_add_tail(&napi→poll_list, &sd→poll_list)를 통해서 softnet_data 구조체의 poll_list에다가 napi_struct 구조체의 poll_list의 내용을 추가하게 됨.