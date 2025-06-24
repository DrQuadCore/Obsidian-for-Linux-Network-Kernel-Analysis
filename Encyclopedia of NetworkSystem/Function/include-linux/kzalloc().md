---
Parameter:
  - size_t
  - gfp_t
Return: void
Location: /include/linux/slab.h
---

```c title=kmalloc_node()
/**
 * kzalloc - allocate memory. The memory is set to zero.
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline __alloc_size(1) void *kzalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags | __GFP_ZERO);
}
```

