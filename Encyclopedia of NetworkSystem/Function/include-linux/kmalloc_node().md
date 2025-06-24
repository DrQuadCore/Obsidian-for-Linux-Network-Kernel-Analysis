---
Parameter:
  - size_t
  - gfp_t
  - int
Return: void
Location: /include/linux/slab.h
---

```c title=kmalloc_node()
static __always_inline __alloc_size(1) void *kmalloc_node(size_t size, gfp_t flags, int node)
{
	if (__builtin_constant_p(size) && size) {
		unsigned int index;

		if (size > KMALLOC_MAX_CACHE_SIZE)
			return kmalloc_large_node(size, flags, node);

		index = kmalloc_index(size);
		return kmalloc_node_trace(
				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
				flags, node, size);
	}
	return __kmalloc_node(size, flags, node);
}
```

