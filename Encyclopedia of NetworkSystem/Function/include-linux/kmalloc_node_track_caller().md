---
Parameter:
  - size_t
  - gfp_t
  - int
Return: void
Location: /include/linux/slab.h
---

```c title=kmalloc_node_track_caller()
void *__kmalloc_node_track_caller(size_t size, gfp_t flags, int node,
				  unsigned long caller) __alloc_size(1);
				  
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
				    _RET_IP_)

```

매크로는 `__kmalloc_node_track_caller` 함수를 호출하며, `_RET_IP_`를 사용하여 호출자의 주소를 자동으로 전달한다.