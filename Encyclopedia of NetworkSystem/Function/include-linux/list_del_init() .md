---
Parameter:
  - list_head
Return: void
Location: /include/linux/list.h
---

```c title=list_del_init()
/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
}
```

