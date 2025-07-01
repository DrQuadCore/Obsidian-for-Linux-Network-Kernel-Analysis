---
Parameter:
  - device
  - size_t
  - dma_addr_t
  - gfp_t
Return: void
Location: /include/linux/dma-mapping.h
---

```c title=dmam_alloc_coherent()
static inline void *dmam_alloc_coherent(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp)
{
	return dmam_alloc_attrs(dev, size, dma_handle, gfp,
			(gfp & __GFP_NOWARN) ? DMA_ATTR_NO_WARN : 0); // [[Encyclopedia of NetworkSystem/Function/kernel-dma/dmam_alloc_attrs().md|dmam_alloc_attrs()]]
}
```

[[Encyclopedia of NetworkSystem/Function/kernel-dma/dmam_alloc_attrs().md|dmam_alloc_attrs()]]
