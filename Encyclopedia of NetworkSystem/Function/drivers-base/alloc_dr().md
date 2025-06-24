---
Parameter:
  - dr_release_t
  - size_t
  - gfp_t
  - int
Return: devres
Location: /drivers/base/devres.c
---

```c title=alloc_dr()
static __always_inline struct devres * alloc_dr(dr_release_t release,
						size_t size, gfp_t gfp, int nid)
{
	size_t tot_size;
	struct devres *dr;

	if (!check_dr_size(size, &tot_size))
		return NULL;

	dr = kmalloc_node_track_caller(tot_size, gfp, nid); // [[kmalloc_node_track_caller()]]
	if (unlikely(!dr))
		return NULL;

	/* No need to clear memory twice */
	if (!(gfp & __GFP_ZERO))
		memset(dr, 0, offsetof(struct devres, data));

	INIT_LIST_HEAD(&dr->node.entry);
	dr->node.release = release;
	return dr;
}
```

[[kmalloc_node_track_caller()]]
