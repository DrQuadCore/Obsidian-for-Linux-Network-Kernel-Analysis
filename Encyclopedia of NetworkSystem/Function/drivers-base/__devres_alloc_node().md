---
Parameter:
  - dr_release_t
  - size_t
  - gfp_t
  - int
  - char
Return: void
Location: /drivers/base/devres.c
---

```c title=__devres_alloc_node()
/**
 * __devres_alloc_node - Allocate device resource data
 * @release: Release function devres will be associated with
 * @size: Allocation size
 * @gfp: Allocation flags
 * @nid: NUMA node
 * @name: Name of the resource
 *
 * Allocate devres of @size bytes.  The allocated area is zeroed, then
 * associated with @release.  The returned pointer can be passed to
 * other devres_*() functions.
 *
 * RETURNS:
 * Pointer to allocated devres on success, NULL on failure.
 */
void *__devres_alloc_node(dr_release_t release, size_t size, gfp_t gfp, int nid,
			  const char *name)
{
	struct devres *dr;

	dr = alloc_dr(release, size, gfp | __GFP_ZERO, nid); //[[alloc_dr()]]
	if (unlikely(!dr))
		return NULL;
	set_node_dbginfo(&dr->node, name, size);
	return dr->data;
}
EXPORT_SYMBOL_GPL(__devres_alloc_node);
```

[[alloc_dr()]]
