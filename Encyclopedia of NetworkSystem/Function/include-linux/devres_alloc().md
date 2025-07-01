---
Parameter:
  - dr_release_t
  - size_t
  - gfp_t
Return: void
Location: /include/linux/device.h
---

```c title=devres_alloc()
void *__devres_alloc_node(dr_release_t release, size_t size, gfp_t gfp,
			  int nid, const char *name) __malloc;
#define devres_alloc(release, size, gfp) \
	__devres_alloc_node(release, size, gfp, NUMA_NO_NODE, #release)
	// [[Encyclopedia of NetworkSystem/Function/drivers-base/__devres_alloc_node().md|__devres_alloc_node()]]
```

[[Encyclopedia of NetworkSystem/Function/drivers-base/__devres_alloc_node().md|__devres_alloc_node()]]

