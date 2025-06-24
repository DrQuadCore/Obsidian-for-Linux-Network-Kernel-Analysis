---
Parameter:
  - device
  - size_t
  - dma_addr_t
  - gfp_t
  - long
Return: void
Location: /kernel/dma/mapping.c
---

```c title=dma_alloc_attrs()
void *dma_alloc_attrs(struct device *dev, size_t size, dma_addr_t *dma_handle,
		gfp_t flag, unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	void *cpu_addr;

	WARN_ON_ONCE(!dev->coherent_dma_mask);

	/*
	 * DMA allocations can never be turned back into a page pointer, so
	 * requesting compound pages doesn't make sense (and can't even be
	 * supported at all by various backends).
	 */
	if (WARN_ON_ONCE(flag & __GFP_COMP))
		return NULL;

	if (dma_alloc_from_dev_coherent(dev, size, dma_handle, &cpu_addr))
		return cpu_addr;

	/* let the implementation decide on the zone to allocate from: */
	flag &= ~(__GFP_DMA | __GFP_DMA32 | __GFP_HIGHMEM);

	if (dma_alloc_direct(dev, ops)) // [[Encyclopedia of NetworkSystem/Function/kernel-dma/dma_alloc_direct().md|dma_alloc_direct()]]
		cpu_addr = dma_direct_alloc(dev, size, dma_handle, flag, attrs);
	else if (ops->alloc)
		cpu_addr = ops->alloc(dev, size, dma_handle, flag, attrs);
	else
		return NULL;

	debug_dma_alloc_coherent(dev, size, *dma_handle, cpu_addr, attrs);
	return cpu_addr;
}
EXPORT_SYMBOL(dma_alloc_attrs);
```

[[Encyclopedia of NetworkSystem/Function/kernel-dma/dma_alloc_direct().md|dma_alloc_direct()]]

> dma_alloc_direct를 통해 device가 direct allocating이 가능하면 IOMMU를 bypass로 하고 해당하는 작업을 수행. 아니라면, ops→alloc 함수를 통해 allocation 수행. alloc이라는 함수는 dma_map_ops 내부에 매핑된 함수 포인터로, dma_map_ops는 device 구조체에 있는것을 확인하였다. 따라서 ice_probe 이전에 이미 매핑이 되었다고 보았다. 이를 따라가 보았지만, 아키텍쳐 종속적인 함수들만 존재하여 우선 포기하였다.